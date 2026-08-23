from __future__ import annotations

import contextlib
import io
import json
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from advisorsai_check import cli, core


class PackagingContractTests(unittest.TestCase):
    def test_html5lib_is_exactly_pinned_and_missing_dependency_is_actionable(self):
        package_root = Path(__file__).resolve().parents[1]
        pyproject = (package_root / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(
            'dependencies = ["html5lib==1.1", "webencodings==0.6.1"]',
            pyproject,
        )
        self.assertEqual(core.html5lib.__version__, "1.1")
        self.assertEqual(core.webencodings.VERSION, "0.6.1")

        core_path = package_root / "advisorsai_check" / "core.py"
        probe = (
            "import builtins,runpy;"
            "real=builtins.__import__;"
            "builtins.__import__=lambda name,*a,**k: "
            "(_ for _ in ()).throw(ModuleNotFoundError(name)) "
            "if name=='html5lib' else real(name,*a,**k);"
            f"runpy.run_path({str(core_path)!r})"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True, text=True, timeout=20, check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(
            "advisorsai-check requires html5lib==1.1; reinstall the package",
            completed.stderr,
        )

    def test_wrong_html5lib_runtime_version_fails_before_parser_use(self):
        package_root = Path(__file__).resolve().parents[1]
        core_path = package_root / "advisorsai_check" / "core.py"
        probe = (
            "import runpy,sys,types;"
            "fake=types.ModuleType('html5lib');fake.__version__='9.9';"
            "sys.modules['html5lib']=fake;"
            f"runpy.run_path({str(core_path)!r})"
        )
        completed = subprocess.run(
            [sys.executable, "-c", probe], capture_output=True, text=True,
            timeout=20, check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("requires html5lib==1.1", completed.stderr)


class TargetSafetyTests(unittest.TestCase):
    def test_rejects_non_web_and_credentialed_targets(self):
        for value in (
            "file:///etc/passwd",
            "https://user:secret@example.com/",
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://example.com:8080/",
            "http://2130706433/",
        ):
            with self.subTest(value=value), self.assertRaises(core.UnsafeTarget):
                core.run(value)

    def test_normalises_unicode_dns_dot_before_validation(self):
        self.assertEqual(
            core.normalise("EXAMPLE。COM/a?Ref=One"),
            "https://example.com/a?Ref=One",
        )

    def test_rejects_any_private_address_in_a_mixed_dns_answer(self):
        fake = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.7", 443)),
        ]
        with patch.object(core.socket, "getaddrinfo", return_value=fake):
            with self.assertRaises(core.UnsafeTarget):
                core._resolve_public("example.com", 443)

    def test_every_redirect_target_is_revalidated(self):
        calls: list[str] = []

        def fake_fetch(url: str):
            calls.append(url)
            if len(calls) == 1:
                return 302, b"", "text/plain", "", "http://127.0.0.1/admin"
            raise AssertionError("cross-origin redirect was fetched")

        with patch.object(core, "_fetch_once", side_effect=fake_fetch):
            self.assertEqual(core._get("https://example.com"), (302, ""))
        self.assertEqual(calls, ["https://example.com"])

    def test_redirects_are_same_origin_only_and_relative_redirects_still_work(self):
        calls: list[str] = []

        def fake_fetch(url: str):
            calls.append(url)
            if len(calls) == 1:
                return 302, b"", "text/plain", "", "/final"
            return 200, b"ok", "text/plain; charset=utf-8", "", ""

        with patch.object(core, "_fetch_once", side_effect=fake_fetch):
            self.assertEqual(core._get("https://example.com/start"), (200, "ok"))
        self.assertEqual(calls, [
            "https://example.com/start", "https://example.com/final",
        ])

    def test_body_limit_is_checked_failure_before_decode(self):
        response = unittest.mock.Mock()
        response.getheader.side_effect = lambda name: (
            "text/plain" if name == "Content-Type" else ""
        )
        response.status = 200
        response.read.return_value = b"x" * (core.MAX_BODY_BYTES + 1)
        connection = unittest.mock.Mock()
        connection.getresponse.return_value = response
        with (
            patch.object(core, "_canonical_target", return_value=(
                "https://example.com/", "example.com", 443, "/", "example.com"
            )),
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "_PinnedHTTPSConnection", return_value=connection),
        ):
            fetched = core._fetch_once("https://example.com")
        self.assertEqual(fetched[0], 200)
        self.assertEqual(fetched[1], b"")
        self.assertEqual(fetched[3], "invalid")
        response.read.assert_called_once_with(core.HTTP_READ_CHUNK)

    def test_dns_deadline_kills_and_reaps_the_resolver_child(self):
        started = time.perf_counter()
        with patch.object(
                core, "_DNS_PROBE", "import time;time.sleep(60)"):
            with self.assertRaises(core.UnsafeTarget):
                core._resolve_public(
                    "example.com", 443, deadline=time.monotonic() + 0.25)
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_trickle_response_cannot_extend_the_total_deadline(self):
        class TrickleResponse:
            status = 200

            @staticmethod
            def getheaders():
                return [("Content-Type", "text/html; charset=utf-8")]

            @staticmethod
            def getheader(name):
                return "" if name == "Location" else None

            @staticmethod
            def read(_amount):
                time.sleep(0.02)
                return b"x"

        connection = unittest.mock.Mock()
        connection.sock = unittest.mock.Mock()
        connection.getresponse.return_value = TrickleResponse()
        started = time.perf_counter()
        with (
            patch.object(core, "_canonical_target", return_value=(
                "https://example.com/", "example.com", 443, "/", "example.com"
            )),
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "_PinnedHTTPSConnection", return_value=connection),
            self.assertRaises(TimeoutError),
        ):
            core._fetch_once(
                "https://example.com", deadline=time.monotonic() + 0.07)
        self.assertLess(time.perf_counter() - started, 0.5)
        self.assertTrue(connection.close.called)

    def test_duplicate_content_type_and_invalid_charset_fail_closed(self):
        duplicate = unittest.mock.Mock()
        duplicate.getheaders.return_value = [
            ("Content-Type", "text/html"),
            ("Content-Type", "text/plain"),
        ]
        with self.assertRaisesRegex(ValueError, "duplicate Content-Type"):
            core._validated_content_type_header(duplicate)

        with patch.object(
                core, "_fetch_once",
                return_value=(
                    200, b"ok", "text/html; charset=no-such-codec", "", "")):
            result = core._get("https://example.com")
        self.assertEqual(result, (200, ""))
        with patch.object(core, "_get", return_value=result):
            self.assertFalse(core.check_home("https://example.com/")[0].ok)

    def test_only_whatwg_charset_labels_decode_and_web_encodings_work(self):
        invalid = ("unicode_escape", "utf-7", "rot_13", "raw-unicode-escape")
        for charset in invalid:
            with self.subTest(charset=charset), patch.object(
                    core, "_fetch_once", return_value=(
                        200, b"ok", f"text/html; charset={charset}", "", "")):
                self.assertEqual(core._get("https://example.com"), (200, ""))

        cases = (
            (b"caf\xc3\xa9", "utf-8", "café"),
            (b"caf\xe9", "windows-1252", "café"),
        )
        for raw, charset, expected in cases:
            with self.subTest(charset=charset), patch.object(
                    core, "_fetch_once", return_value=(
                        200, raw, f"text/html; charset={charset}", "", "")):
                self.assertEqual(
                    core._get("https://example.com"), (200, expected))

    def test_content_encoding_is_unique_and_identity_only(self):
        duplicate = unittest.mock.Mock()
        duplicate.getheaders.return_value = [
            ("Content-Encoding", "identity"),
            ("Content-Encoding", "gzip"),
        ]
        with self.assertRaisesRegex(ValueError, "duplicate Content-Encoding"):
            core._validated_content_encoding_header(duplicate)
        for value in ("gzip", "deflate", "br", "identity, gzip"):
            response = unittest.mock.Mock()
            response.getheaders.return_value = [("Content-Encoding", value)]
            with self.subTest(value=value), self.assertRaises(ValueError):
                core._validated_content_encoding_header(response)
        for value in (None, "", "identity", "IDENTITY"):
            response = unittest.mock.Mock()
            response.getheaders.return_value = (
                [] if not value else [("Content-Encoding", value)])
            self.assertIn(
                core._validated_content_encoding_header(response), {"", "identity"})
        forged = core._FetchDocument(
            200, "<h1>forged</h1>", "text/html", "gzip")
        self.assertFalse(core._content_type(
            forged, frozenset({"text/html"}))[0])

    def test_http_error_status_survives_empty_or_mislabeled_error_body(self):
        cases = (
            (404, b"", ""),
            (429, b"not html", "application/octet-stream"),
            (503, b"\xff", "text/html; charset=utf-8"),
        )
        for status, body, content_type in cases:
            with self.subTest(status=status), patch.object(
                core, "_fetch_once",
                return_value=(status, body, content_type, "gzip", ""),
            ):
                result = core._get("https://example.com/")
            self.assertEqual(result.status, status)
            self.assertEqual(result.body, "")
            with patch.object(core, "_get", return_value=result):
                signal = core.check_home("https://example.com/")[0]
            self.assertIs(signal.ok, False)
            self.assertIn(f"HTTP {status}", signal.detail)

        response = unittest.mock.Mock()
        response.status = 503
        response.getheader.return_value = ""
        response.getheaders.side_effect = AssertionError(
            "error Content-Type must not be parsed")
        response.read.side_effect = AssertionError("error body must not be read")
        connection = unittest.mock.Mock()
        connection.sock = None
        connection.getresponse.return_value = response
        with (
            patch.object(core, "_canonical_target", return_value=(
                "https://example.com/", "example.com", 443, "/", "example.com"
            )),
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "_PinnedHTTPSConnection", return_value=connection),
        ):
            fetched = core._fetch_once(
                "https://example.com/", deadline=time.monotonic() + 1.0)
        self.assertEqual(fetched, (503, b"", "", "", ""))
        response.read.assert_not_called()

        invalid_success = unittest.mock.Mock()
        invalid_success.status = 200
        invalid_success.getheader.return_value = ""
        invalid_success.getheaders.return_value = [
            ("Content-Type", "text/html"),
            ("Content-Type", "text/plain"),
        ]
        connection.getresponse.return_value = invalid_success
        with (
            patch.object(core, "_canonical_target", return_value=(
                "https://example.com/", "example.com", 443, "/", "example.com"
            )),
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "_PinnedHTTPSConnection", return_value=connection),
        ):
            fetched = core._fetch_once(
                "https://example.com/", deadline=time.monotonic() + 1.0)
        self.assertEqual(fetched, (200, b"", "", "invalid", ""))
        document = core._FetchDocument(200, "", "", "invalid")
        with patch.object(core, "_get", return_value=document):
            self.assertFalse(core.check_home("https://example.com/")[0].ok)

    def test_http_404_is_a_complete_measured_failure_not_transport_loss(self):
        """A real 404 is marketable evidence, not an unavailable check.

        This deliberately exercises the full runner through ``_fetch_once``.
        Mutating ``_get`` to collapse HTTP errors into status 0 makes the
        report partial and this assertion fail.
        """
        with (
            patch.object(
                core, "_fetch_once",
                return_value=(404, b"", "", "", ""),
            ),
            patch.object(
                core, "_resolve_public", return_value=["93.184.216.34"]),
        ):
            report = core.run("https://example.com/missing")

        self.assertTrue(report.successful)
        self.assertEqual(report.coverage_percent, 100)
        self.assertIsNotNone(report.score)
        self.assertLess(report.score, 100)
        self.assertEqual(report.errors, [])
        home = next(signal for signal in report.signals if signal.key == "home")
        self.assertIs(home.ok, False)
        self.assertIn("HTTP 404", home.detail)
        self.assertTrue(any(
            signal.ok is False and signal.weight > 0
            for signal in report.signals
        ))


class RobotsPolicyTests(unittest.TestCase):
    def _check(self, body: str):
        with patch.object(core, "_get", return_value=(200, body)):
            return core.check_robots("https://example.com/")[0]

    def test_training_bot_block_is_note_not_failed_answer_discovery(self):
        signal = self._check("User-agent: GPTBot\nDisallow: /\n")
        self.assertTrue(signal.ok)
        self.assertIn("training/model-use", signal.detail)

    def test_search_bot_block_fails(self):
        signal = self._check("User-agent: OAI-SearchBot\nDisallow: /\n")
        self.assertFalse(signal.ok)
        self.assertIn("OAI-SearchBot", signal.detail)

    def test_submitted_path_is_checked_not_only_root(self):
        with patch.object(
            core,
            "_get",
            return_value=(200, "User-agent: OAI-SearchBot\nDisallow: /private/*\n"),
        ):
            blocked = core.check_robots("https://example.com/private/report")[0]
            public = core.check_robots("https://example.com/public/report")[0]
        self.assertFalse(blocked.ok)
        self.assertTrue(public.ok)

    def test_allow_wins_when_equally_specific_for_submitted_path(self):
        signal = self._check(
            "User-agent: OAI-SearchBot\n"
            "Disallow: /reports/*\n"
            "Allow: /reports/*\n"
        )
        groups = core._robots_groups(
            "User-agent: OAI-SearchBot\n"
            "Disallow: /reports/*\n"
            "Allow: /reports/*\n"
        )
        self.assertFalse(core._path_blocked(groups, "OAI-SearchBot", "/reports/a"))
        self.assertTrue(signal.ok)

    def test_mutation_rfc9309_unreserved_octets_are_normalised_before_matching(self):
        groups = core._robots_groups(
            "User-agent: OAI-SearchBot\n"
            "Disallow: /foo%62ar\n"
            "Allow: /foobar\n"
        )
        # %62 is the unreserved ASCII character "b".  Both rules therefore
        # have equal specificity and Allow must win the tie.
        self.assertFalse(
            core._path_blocked(groups, "OAI-SearchBot", "/foobar"))

    def test_mutation_rfc9309_reserved_octets_stay_percent_encoded(self):
        groups = core._robots_groups(
            "User-agent: OAI-SearchBot\nDisallow: /private%2freport\n")
        self.assertTrue(core._path_blocked(
            groups, "OAI-SearchBot", "/private%2Freport"))
        self.assertFalse(core._path_blocked(
            groups, "OAI-SearchBot", "/private/report"))

    def test_specific_allow_overrides_wildcard_block(self):
        signal = self._check(
            "User-agent: *\nDisallow: /\n"
            "User-agent: OAI-SearchBot\nAllow: /\n"
            "User-agent: ChatGPT-User\nAllow: /\n"
            "User-agent: Claude-SearchBot\nAllow: /\n"
            "User-agent: Claude-User\nAllow: /\n"
            "User-agent: PerplexityBot\nAllow: /\n"
            "User-agent: Perplexity-User\nAllow: /\n"
            "User-agent: Googlebot\nAllow: /\n"
            "User-agent: Bingbot\nAllow: /\n"
        )
        self.assertTrue(signal.ok)

    def test_new_agent_after_rules_starts_a_new_group(self):
        groups = core._robots_groups(
            "User-agent: *\nDisallow: /private\n"
            "User-agent: GPTBot\nDisallow: /\n"
        )
        self.assertFalse(core._root_blocked(groups, "OAI-SearchBot"))
        self.assertTrue(core._root_blocked(groups, "GPTBot"))

    def test_llms_txt_is_informational_not_part_of_score(self):
        with patch.object(core, "_get", return_value=(404, "")):
            signal = core.check_llms_txt("https://example.com/")[0]
        self.assertFalse(signal.ok)
        self.assertEqual(signal.weight, 0)
        self.assertIn("not a web standard", signal.detail)

    def test_robots_4xx_is_unavailable_and_declares_no_restrictions(self):
        with patch.object(core, "_get", return_value=(403, "blocked")):
            signal = core.check_robots("https://example.com/")[0]
        self.assertTrue(signal.ok)
        self.assertIn("HTTP 403", signal.detail)

    def test_robots_5xx_is_treated_as_temporarily_disallowed(self):
        with patch.object(core, "_get", return_value=(503, "unavailable")):
            signal = core.check_robots("https://example.com/")[0]
        self.assertFalse(signal.ok)

    def test_terminal_redirect_is_checked_not_a_network_failure(self):
        with patch.object(core, "_get", return_value=(302, "")):
            signal = core.check_robots("https://example.com/")[0]
        self.assertIs(signal.ok, False)
        self.assertIn("HTTP 302", signal.detail)

    def test_only_exact_http_200_is_a_full_page_or_robots_representation(self):
        for status in (202, 206, 226):
            with (
                self.subTest(status=status),
                patch.object(
                    core,
                    "_get",
                    return_value=(status, "<h1>forged partial body</h1>"),
                ),
            ):
                home = core.check_home("https://example.com/")
                robots = core.check_robots("https://example.com/")
            self.assertEqual(
                {signal.key for signal in home},
                {
                    "home", "title", "description", "structured_business",
                    "structured_offering", "h1", "canonical",
                },
            )
            self.assertTrue(all(signal.ok is False for signal in home))
            self.assertFalse(robots[0].ok)
            self.assertIn("full HTTP 200", robots[0].detail)

    def test_robots_evaluator_timeout_kills_and_reaps_child(self):
        class Process:
            def __init__(self):
                self.killed = False
                self.communicates = 0
                self.returncode = None

            def communicate(self, input=None, timeout=None):
                self.communicates += 1
                if not self.killed:
                    self.timeout = timeout
                    raise subprocess.TimeoutExpired("robots", timeout)
                self.returncode = -9
                return b"", b""

            def kill(self):
                self.killed = True

            def poll(self):
                return self.returncode

        process = Process()
        with (
            patch.object(core.subprocess, "Popen", return_value=process),
            self.assertRaises(TimeoutError),
        ):
            core._evaluate_robots_bounded(
                "User-agent: *\nDisallow: /", "/",
                deadline=time.monotonic() + 0.05,
            )
        self.assertTrue(process.killed)
        self.assertEqual(process.communicates, 2)
        self.assertGreater(process.timeout, 0)
        self.assertLessEqual(process.timeout, 0.05)

    def test_network_failure_is_unchecked_not_a_site_failure(self):
        checks = (
            core.check_home,
            core.check_robots,
            core.check_llms_txt,
            core.check_sitemap,
        )
        report = core.Report(url="https://example.com/")
        with patch.object(core, "_get", return_value=(0, "")):
            for check in checks:
                report.signals.extend(check(report.url))
        self.assertTrue(report.signals)
        self.assertTrue(all(signal.ok is None for signal in report.signals))
        self.assertFalse(report.successful)
        self.assertIsNone(report.score)
        self.assertLess(report.coverage_percent, 100)

    def test_empty_report_is_unsuccessful_with_zero_coverage(self):
        report = core.Report(url="https://example.com/")
        self.assertFalse(report.successful)
        self.assertIsNone(report.score)
        self.assertEqual(report.coverage_percent, 0)

        report.signals.append(core.Signal("llms_txt", True, "note", 0))
        self.assertFalse(report.successful)
        self.assertIsNone(report.score)
        self.assertEqual(report.coverage_percent, 0)

    def test_report_contract_is_closed_complete_unique_and_weight_pinned(self):
        def complete_signals():
            return [
                core.Signal(key, True, f"{key} receipt", weight)
                for key, weight in core.SIGNAL_WEIGHT_CONTRACT.items()
                if key in core.REQUIRED_SIGNAL_KEYS
            ]

        clean = core.Report(
            url="https://example.com/", signals=complete_signals())
        self.assertTrue(clean.successful)
        self.assertEqual(clean.coverage_percent, 100)
        self.assertEqual(clean.score, 100)

        mutations = {
            "home-only": [core.Signal("home", True, "home receipt", 0)],
            "unknown": complete_signals()
            + [core.Signal("invented", True, "unknown receipt", 0)],
            "empty-stage": [
                signal for signal in complete_signals()
                if signal.key != "robots"
            ],
            "wrong-weight": [
                core.Signal(
                    signal.key,
                    signal.ok,
                    signal.detail,
                    signal.weight + (1 if signal.key == "title" else 0),
                )
                for signal in complete_signals()
            ],
            "duplicate-conflict": complete_signals()
            + [core.Signal("robots", False, "conflicting receipt", 7)],
            "empty-detail": [
                core.Signal(
                    signal.key,
                    signal.ok,
                    "" if signal.key == "sitemap" else signal.detail,
                    signal.weight,
                )
                for signal in complete_signals()
            ],
        }
        for label, signals in mutations.items():
            with self.subTest(label=label):
                report = core.Report(
                    url="https://example.com/", signals=signals)
                self.assertFalse(report.successful)
                self.assertIsNone(report.score)
                self.assertLess(report.coverage_percent, 100)

    def test_report_contract_rejects_incoherent_page_and_jsonld_diagnostics(self):
        def complete_signals():
            return [
                core.Signal(key, True, f"{key} receipt", weight)
                for key, weight in core.SIGNAL_WEIGHT_CONTRACT.items()
                if key in core.REQUIRED_SIGNAL_KEYS
            ]

        home_false_with_derived_true = [
            core.Signal(
                signal.key,
                False if signal.key == "home" else signal.ok,
                signal.detail,
                signal.weight,
            )
            for signal in complete_signals()
        ]
        invalid_diagnostics = {
            "positive-diagnostic": complete_signals() + [
                core.Signal("jsonld_valid", True, "forged bonus", 1)
            ],
            "terminal-home-diagnostic": [
                core.Signal(
                    signal.key,
                    False if signal.key in (
                        {"home"} | core._PAGE_DERIVED_SIGNAL_KEYS
                    ) else signal.ok,
                    signal.detail,
                    signal.weight,
                )
                for signal in complete_signals()
            ] + [core.Signal("jsonld_valid", False, "out of context", 1)],
        }
        mutations = {
            "home-false-derived-true": home_false_with_derived_true,
            **invalid_diagnostics,
        }
        for label, signals in mutations.items():
            with self.subTest(label=label):
                report = core.Report(
                    url="https://example.com/", signals=signals)
                self.assertFalse(report.successful)
                self.assertIsNone(report.score)
                self.assertLess(report.coverage_percent, 100)

        base = complete_signals()
        base[1] = core.Signal(
            base[1].key, False, base[1].detail, base[1].weight)
        without_diagnostic = core.Report(
            url="https://example.com/", signals=base)
        with_negative_diagnostic = core.Report(
            url="https://example.com/",
            signals=base + [
                core.Signal(
                    "jsonld_valid", False,
                    "a JSON-LD block does not parse", 1,
                )
            ],
        )
        self.assertTrue(with_negative_diagnostic.successful)
        self.assertLessEqual(
            with_negative_diagnostic.score, without_diagnostic.score)

    def test_unchecked_zero_weight_receipts_reduce_coverage(self):
        complete = [
            core.Signal(key, True, f"{key} receipt", weight)
            for key, weight in core.SIGNAL_WEIGHT_CONTRACT.items()
            if key in core.REQUIRED_SIGNAL_KEYS
        ]
        llms_unchecked = core.Report(
            url="https://example.com/",
            signals=[
                core.Signal(
                    signal.key,
                    None if signal.key == "llms_txt" else signal.ok,
                    signal.detail,
                    signal.weight,
                )
                for signal in complete
            ],
        )
        self.assertFalse(llms_unchecked.successful)
        self.assertIsNone(llms_unchecked.score)
        self.assertEqual(llms_unchecked.coverage_percent, 92)

        home_unchecked = core.Report(
            url="https://example.com/",
            signals=[
                core.Signal(
                    signal.key,
                    None if signal.key in (
                        {"home"} | core._PAGE_DERIVED_SIGNAL_KEYS
                    ) else signal.ok,
                    signal.detail,
                    signal.weight,
                )
                for signal in complete
            ],
        )
        self.assertFalse(home_unchecked.successful)
        self.assertIsNone(home_unchecked.score)
        self.assertLess(home_unchecked.coverage_percent, 100)

    def test_run_emits_one_receipt_for_every_official_stage(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page '
            'description for deterministic machine-readable checks.">'
            '<link rel="canonical" href="https://example.com/"><script '
            'type="application/ld+json">{"@context":"https://schema.org",'
            '"@graph":[{"@type":"Organization","name":"Example"},'
            '{"@type":"Service","name":"Audit"}]}</script></head>'
            '<body><h1>Visible heading</h1></body></html>'
        )
        sitemap = (
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://example.com/</loc></url></urlset>'
        )

        def fetched(url: str, *, deadline=None):
            _ = deadline
            if url.endswith("/robots.txt"):
                return 200, "User-agent: *\nAllow: /"
            if url.endswith("/llms.txt"):
                return 200, "x" * 201
            if url.endswith("/sitemap.xml"):
                return 200, sitemap
            return 200, html

        with (
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "_get", side_effect=fetched),
            # This is the all-stages success contract.  Allow Windows process
            # startup under parallel suite load; timeout mutations have their
            # own deliberately short, fail-closed tests.
            patch.object(core, "TIMEOUT", 20),
        ):
            report = core.run("https://example.com/")
        keys = [signal.key for signal in report.signals]
        self.assertEqual(set(keys), core.REQUIRED_SIGNAL_KEYS)
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(all(
            signal.weight == core.SIGNAL_WEIGHT_CONTRACT[signal.key]
            for signal in report.signals
        ))
        self.assertTrue(report.successful, report.errors)
        self.assertEqual(report.coverage_percent, 100)

    def test_element_text_excludes_inert_subtrees_but_keeps_visible_tails(self):
        namespace = f"{{{core._HTML_NAMESPACE}}}"
        root = core.ET.Element(namespace + "h1")
        root.text = "Visible start "
        for tag in ("script", "style", "template", "noscript"):
            inert = core.ET.SubElement(root, namespace + tag)
            inert.text = f"forged {tag} text"
            nested = core.ET.SubElement(inert, namespace + "span")
            nested.text = f"forged nested {tag} text"
            inert.tail = f" visible tail {tag} "
        active = core.ET.SubElement(root, namespace + "span")
        active.text = "visible active text"
        self.assertEqual(
            core._element_text(root),
            "Visible start visible tail script visible tail style "
            "visible tail template visible tail noscript visible active text",
        )

    def test_user_fetcher_block_is_informational_only(self):
        signal = self._check("User-agent: ChatGPT-User\nDisallow: /\n")
        self.assertTrue(signal.ok)
        self.assertIn("informational only", signal.detail)

    def test_meta_description_attribute_order_does_not_matter(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta content="A sufficiently long description that explains this page to a machine reader." '
            'name="description"></head><body><h1>One heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            signals = core.check_home("https://example.com/")
        description = next(item for item in signals if item.key == "description")
        self.assertTrue(description.ok)

    def test_html5_first_duplicate_attribute_wins_for_every_semantic_field(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="attacker" name="description" '
            'content="A sufficiently long forged description that must not count.">'
            '<script type="text/plain" type="application/ld+json">'
            '{"@context":"https://schema.org","@graph":['
            '{"@type":"Organization","name":"Forged"},'
            '{"@type":"Service","name":"Forged"}]}</script>'
            '<link rel="alternate" rel="canonical" href="" '
            'href="https://public.example.net/forged">'
            '</head><body><h1>One heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        for key in (
            "description", "structured_business", "structured_offering",
            "canonical",
        ):
            with self.subTest(key=key):
                self.assertFalse(by_key[key].ok)

    def test_html_ascii_whitespace_and_select_tree_rules_block_forged_signals(self):
        """Mutation guard: NBSP is data, never an HTML token delimiter."""
        nbsp = "\u00a0"
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            f'<meta name="description{nbsp}" content="A sufficiently long '
            'forged description that must not count for this page.">'
            f'<script type="application/ld+json{nbsp}">'
            '{"@context":"https://schema.org","@graph":['
            '{"@type":"Organization","name":"Forged"},'
            '{"@type":"Service","name":"Forged"}]}</script>'
            f'<link rel="alternate{nbsp}canonical" '
            'href="https://public.example.net/forged">'
            '</head><body><select><h1>Forged heading</h1></select>'
            '</body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        for key in (
            "description", "structured_business", "structured_offering",
            "canonical", "h1",
        ):
            with self.subTest(key=key):
                self.assertFalse(by_key[key].ok, by_key[key].detail)
        self.assertNotIn("jsonld_valid", by_key)


class SemanticDocumentTests(unittest.TestCase):
    def _h1_signal(self, body: str):
        html = f"<html><head><title>A descriptive page title</title></head><body>{body}</body></html>"
        with patch.object(core, "_get", return_value=(200, html)):
            return next(
                signal for signal in core.check_home("https://example.com/")
                if signal.key == "h1"
            )

    def test_visible_h1_excludes_hidden_inert_and_aria_hidden_ancestry(self):
        signal = self._h1_signal(
            '<section hidden><h1>forged hidden</h1></section>'
            '<section inert><h1>forged inert</h1></section>'
            '<section aria-hidden="true"><h1>forged aria</h1></section>'
            '<h1>Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)

    def test_visible_h1_style_cascade_hides_display_visibility_and_opacity(self):
        signal = self._h1_signal(
            '<h1 style="dis\\70 lay:none">forged display</h1>'
            '<h1 style="visibility: visible; visibility: hidden">forged visibility</h1>'
            '<h1 style="opacity: 0% !important; opacity:1">forged opacity</h1>'
            '<h1 style="display:none;display:block">Visible cascade</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible cascade", signal.detail)

    def test_visible_h1_handles_calc_content_visibility_vars_and_popovers(self):
        signal = self._h1_signal(
            '<h1 style="opacity:calc(0)">forged calc opacity</h1>'
            '<h1 style="content-visibility:hidden">forged content visibility</h1>'
            '<section style="--closed:none">'
            '<h1 style="display:var(--closed)">forged inherited var</h1>'
            '</section>'
            '<h1 style="display:var(--missing, none)">forged var fallback</h1>'
            '<h1 popover>forged closed popover</h1>'
            '<section style="visibility:hidden">'
            '<h1 style="visibility:visible">Visible override</h1>'
            '</section>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible override", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_visible_h1_rejects_computed_zero_cycle_fallback_and_invalid_cascade(self):
        signal = self._h1_signal(
            '<h1 style="opacity:calc(1 - 1)">forged calc number</h1>'
            '<h1 style="opacity:calc(100% - 100%)">forged calc percent</h1>'
            '<h1 style="--alpha:calc(1 - 1);opacity:var(--alpha)">'
            'forged variable calc</h1>'
            '<h1 style="opacity:-0.01">forged negative opacity</h1>'
            '<h1 style="--loop:var(--loop);display:var(--loop,none)">'
            'forged cycle fallback</h1>'
            '<h1 style="display:none;display:bogus">forged display typo</h1>'
            '<h1 style="display:none;display:list-item flex">'
            'forged display grammar</h1>'
            '<h1 style="display:none;display:var(--bad name,block)">'
            'forged variable name</h1>'
            '<h1 style="visibility:hidden;visibility:var(--missing)">'
            'forged visibility typo</h1>'
            '<h1 style="opacity:0;opacity:not-a-number">'
            'forged opacity typo</h1>'
            '<h1 style="opacity:0;opacity:calc (1)">'
            'forged calc token</h1>'
            '<h1>Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_visible_h1_css_extensions_do_not_hide_visible_values(self):
        visible_styles = (
            "opacity:calc(0 + 1)",
            "opacity:calc(1-0)",
            "opacity:calc(100%-0%)",
            "--mode:block;display:var(--mode, none)",
            "--loop:var(--loop);display:var(--loop, block)",
            "display:none;display:grid",
            "display:none;display:inline flex",
            "visibility:hidden;visibility:visible",
            "opacity:0;opacity:calc(1)",
            "content-visibility:auto",
            "visibility:initial",
        )
        for style in visible_styles:
            with self.subTest(style=style):
                signal = self._h1_signal(
                    f'<h1 style="{style}">Visible heading</h1>')
                self.assertTrue(signal.ok, signal.detail)
                self.assertIn("Visible heading", signal.detail)

    def test_visible_h1_rejects_min_max_clamp_and_unbounded_calc_zero(self):
        long_zero = "calc(1 - 1" + " + 0" * 400 + ")"
        signal = self._h1_signal(
            '<h1 style="opacity:min(0,1)">forged min</h1>'
            '<h1 style="opacity:max(0,0)">forged max</h1>'
            '<h1 style="opacity:clamp(0,0,1)">forged clamp</h1>'
            '<h1 style="opacity:calc(min(1,max(0,0)))">'
            'forged nested math</h1>'
            f'<h1 style="opacity:{long_zero}">forged long calc</h1>'
            '<h1 style="opacity:0;opacity:min(1,)">'
            'forged invalid min cascade</h1>'
            '<h1 style="opacity:0;opacity:clamp(0,1)">'
            'forged invalid clamp cascade</h1>'
            '<h1>Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

        long_one = "calc(1" + " + 0" * 400 + ")"
        for style in (
            "opacity:min(1,1)",
            "opacity:max(0,1)",
            "opacity:clamp(0,1,1)",
            f"opacity:{long_one}",
        ):
            with self.subTest(style=style):
                visible = self._h1_signal(
                    f'<h1 style="{style}">Visible control</h1>')
                self.assertTrue(visible.ok, visible.detail)
                self.assertIn("Visible control", visible.detail)

    def test_visible_h1_evaluates_all_context_free_css_math_functions(self):
        hidden_math = (
            "round(0.4)",
            "round(nearest,0.4,1)",
            "round(up,-0.4,1)",
            "mod(2,1)",
            "rem(2,1)",
            "abs(0)",
            "sign(0)",
            "hypot(0,0)",
            "pow(0,2)",
            "sqrt(0)",
            "exp(-infinity)",
            "log(1)",
            "calc(infinity)",
            "calc(-infinity)",
            "calc(NaN)",
            "calc(1/0)",
            "sqrt(-1)",
            "log(-1)",
            "mod(1,0)",
            "pow(-1,.5)",
        )
        body = "".join(
            f'<h1 style="opacity:{expression}">forged {index}</h1>'
            for index, expression in enumerate(hidden_math)
        ) + '<h1>Visible heading</h1>'
        signal = self._h1_signal(body)
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

        visible_math = (
            "round(1.4)",
            "round(down,1.9,1)",
            "mod(3,2)",
            "rem(3,2)",
            "abs(-1)",
            "sign(2)",
            "hypot(1,0)",
            "pow(1,10)",
            "sqrt(1)",
            "exp(0)",
            "log(e)",
        )
        for expression in visible_math:
            with self.subTest(expression=expression):
                visible = self._h1_signal(
                    f'<h1 style="opacity:{expression}">'
                    'Visible math control</h1>')
                self.assertTrue(visible.ok, visible.detail)
                self.assertIn("Visible math control", visible.detail)

    def test_important_requires_literal_bang_and_ascii_css_whitespace(self):
        signal = self._h1_signal(
            '<h1 style="display:none !\\69mportant;display:block">'
            'forged escaped word</h1>'
            '<h1 style="content-visibility:hidden !\\000069mportant;'
            'content-visibility:visible">forged six-digit word</h1>'
            '<h1 style="display:none !/**/important;display:block">'
            'forged commented priority</h1>'
            '<h1>Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

        visible_styles = (
            "display:none \\21 important;display:block",
            "display:none \\000021 important;display:block",
            "display:none !\u00a0important;display:block",
            "display:none !\\ important;display:block",
            "display:none \uff01important;display:block",
        )
        for style in visible_styles:
            with self.subTest(style=style):
                visible = self._h1_signal(
                    f'<h1 style="{style}">Visible priority control</h1>')
                self.assertTrue(visible.ok, visible.detail)
                self.assertIn("Visible priority control", visible.detail)

    def test_custom_property_wide_keywords_use_fallback_and_inheritance(self):
        signal = self._h1_signal(
            '<h1 style="--mode:initial;display:var(--mode,none)">'
            'forged initial fallback</h1>'
            '<h1 style="--mode:\\69nitial;display:var(--mode,none)">'
            'forged escaped initial</h1>'
            '<h1 style="--mode:inherit;display:var(--mode,none)">'
            'forged missing inherit</h1>'
            '<h1 style="--mode:unset;display:var(--mode,none)">'
            'forged missing unset</h1>'
            '<section style="--mode:none">'
            '<h1 style="--mode:inherit;display:var(--mode,block)">'
            'forged inherited none</h1>'
            '<h1 style="--mode:unset;display:var(--mode,block)">'
            'forged unset none</h1></section>'
            '<section style="--mode:block">'
            '<h1 style="--mode:inherit;display:var(--mode,none)">'
            'Visible inherited block</h1></section>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible inherited block", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_escaped_custom_names_obey_identifier_and_hex_boundaries(self):
        signal = self._h1_signal(
            '<h1 style="--\\78:none;display:var(--\\000078,block)">'
            'forged escaped variable</h1>'
            '<h1 style="--\\000078 :none;display:var(--x,block)">'
            'forged terminated escape</h1>'
            '<h1 style="--bad\\ name:none;display:var(--bad\\ name,block)">'
            'forged escaped-space variable</h1>'
            '<h1 style="display:none;display:blo\\">'
            'forged truncated escape</h1>'
            '<h1>Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

        for style in (
            # Six hex digits are consumed; the seventh is a literal suffix.
            "--\\0000780:none;display:var(--x,block)",
            # Custom-property names remain case-sensitive after decoding.
            "--\\58:none;display:var(--x,block)",
            "--\\78:block;display:var(--\\000078,none)",
        ):
            with self.subTest(style=style):
                visible = self._h1_signal(
                    f'<h1 style="{style}">Visible boundary control</h1>')
                self.assertTrue(visible.ok, visible.detail)
                self.assertIn("Visible boundary control", visible.detail)

    def test_nested_fallbacks_resolve_after_escaped_custom_names(self):
        signal = self._h1_signal(
            '<h1 style="display:var(--\\78-missing,'
            'var(--\\79-missing,none))">forged nested fallback</h1>'
            '<h1 style="--\\66 oo:var(--missing,var(--other,none));'
            'display:var(--foo,block)">forged nested custom value</h1>'
            '<h1 style="display:var(--\\78-missing,'
            'var(--\\79-missing,block))">Visible nested control</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible nested control", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_var_resolution_has_no_legacy_32_substitution_cutoff(self):
        depth = 80
        hidden_chain = ";".join(
            [f"--v{index}:var(--v{index + 1})" for index in range(depth)]
            + [f"--v{depth}:none", "display:var(--v0)"]
        )
        visible_chain = ";".join(
            [f"--v{index}:var(--v{index + 1})" for index in range(depth)]
            + [f"--v{depth}:block", "display:var(--v0)"]
        )
        hidden = self._h1_signal(
            f'<h1 style="{hidden_chain}">forged long chain</h1>'
            '<h1>Visible heading</h1>')
        self.assertTrue(hidden.ok, hidden.detail)
        self.assertIn("Visible heading", hidden.detail)
        self.assertNotIn("forged", hidden.detail)

        visible = self._h1_signal(
            f'<h1 style="{visible_chain}">Visible long chain</h1>')
        self.assertTrue(visible.ok, visible.detail)
        self.assertIn("Visible long chain", visible.detail)

    def test_unknown_opacity_functions_fail_closed_but_strings_do_not(self):
        signal = self._h1_signal(
            '<h1 style="opacity:future-alpha(1)">forged unknown</h1>'
            '<h1 style="opacity:calc(future-alpha(1))">'
            'forged nested unknown</h1>'
            '<h1 style="opacity:calc(1)">Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

        visible = self._h1_signal(
            '<h1 style="opacity:1;--note:&quot;future-alpha(0)&quot;">'
            'Visible string control</h1>')
        self.assertTrue(visible.ok, visible.detail)
        self.assertIn("Visible string control", visible.detail)

    def test_css_token_boundaries_keep_comments_strings_and_functions_distinct(self):
        hidden = self._h1_signal(
            '<h1 style="opacity:\\63 alc(0)">forged escaped calc</h1>'
            '<h1 style="/**/display: n\\6f ne">forged escaped none</h1>'
            '<h1 style="display:none;display:inline\\ flex">'
            'forged escaped keyword separator</h1>'
            '<h1 style="display:none;display:inline\u00a0flex">'
            'forged unicode keyword separator</h1>'
            '<h1>Visible heading</h1>')
        self.assertTrue(hidden.ok, hidden.detail)
        self.assertIn("Visible heading", hidden.detail)
        self.assertNotIn("forged", hidden.detail)

        visible = self._h1_signal(
            '<h1 style="dis/**/play:none;opacity:calc/**/(0);'
            '--note:&quot;;display:none;var(--x)&quot;">'
            'Visible token control</h1>')
        self.assertTrue(visible.ok, visible.detail)
        self.assertIn("Visible token control", visible.detail)

    def test_css_numeric_grammar_enforces_whitespace_and_type_algebra(self):
        hidden = self._h1_signal(
            '<h1 style="opacity:calc(1 - 1)">forged number sum</h1>'
            '<h1 style="opacity:calc(100% - 100%)">forged percent sum</h1>'
            '<h1 style="opacity:calc(100% / 100% - 1)">'
            'forged typed division</h1>'
            '<h1 style="opacity:min(0%,calc(10% - 10%))">'
            'forged typed min</h1>'
            '<h1>Visible heading</h1>')
        self.assertTrue(hidden.ok, hidden.detail)
        self.assertIn("Visible heading", hidden.detail)
        self.assertNotIn("forged", hidden.detail)

        visible = self._h1_signal(
            '<section style="opacity:calc(1-1)">'
            '<section style="opacity:calc(1 + 1%)">'
            '<section style="opacity:calc(1% * 1%)">'
            '<section style="opacity:min(0,0%)">'
            '<h1>Visible typed controls</h1>'
            '</section></section></section></section>')
        self.assertTrue(visible.ok, visible.detail)
        self.assertIn("Visible typed controls", visible.detail)

    def test_stylesheet_rules_hide_matching_headings_and_ancestors(self):
        signal = self._h1_signal(
            '<style>'
            '.hidden{display:none}'
            'section > h1.child{visibility:hidden}'
            '#opaque{opacity:calc(1 - 1)}'
            '.ancestor{display:none}.ancestor h1{display:block}'
            '#priority{display:none!important}'
            '@media all{.media{display:none}}'
            ':root{--sheet-hide:none}.sheet-var{display:var(--sheet-hide)}'
            '</style>'
            '<h1 class="hidden">forged class</h1>'
            '<section><h1 class="child">forged child</h1></section>'
            '<h1 id="opaque">forged opacity</h1>'
            '<section class="ancestor"><h1>forged ancestor</h1></section>'
            '<h1 id="priority" style="display:block">forged important</h1>'
            '<h1 class="media">forged media</h1>'
            '<h1 class="sheet-var">forged stylesheet variable</h1>'
            '<h1>Visible heading</h1>')
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_stylesheet_cascade_and_inert_rules_keep_visible_controls(self):
        bodies = (
            '<style>.x{display:none}.x{display:block}</style>'
            '<h1 class="x">Visible source order</h1>',
            '<style>#x{display:none}</style>'
            '<h1 id="x" style="display:block">Visible inline</h1>',
            '<style>#x{display:none!important}</style>'
            '<h1 id="x" style="display:block!important">'
            'Visible inline important</h1>',
            '<template><style>h1{display:none}</style></template>'
            '<style>.other{display:none}'
            '@media print{h1{display:none}}'
            '@media only print{h1{visibility:hidden}}'
            '</style>'
            '<h1>Visible inert and unmatched</h1>',
        )
        for body in bodies:
            with self.subTest(body=body):
                signal = self._h1_signal(body)
                self.assertTrue(signal.ok, signal.detail)
                self.assertIn("Visible", signal.detail)

    def test_visibility_override_cannot_escape_hard_hidden_ancestor(self):
        signal = self._h1_signal(
            '<section style="display:none;visibility:hidden">'
            '<h1 style="visibility:visible">forged display ancestor</h1>'
            '</section>'
            '<section contenteditable style="content-visibility:hidden">'
            '<h1 style="visibility:visible">forged content ancestor</h1>'
            '</section>'
            '<h1>Visible heading</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible heading", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_visible_h1_closed_dialog_and_details_keep_only_first_summary(self):
        signal = self._h1_signal(
            '<dialog><h1>forged dialog</h1></dialog>'
            '<details><summary><h1>Visible summary</h1></summary>'
            '<h1>forged details body</h1></details>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible summary", signal.detail)

    def test_visible_h1_excludes_hidden_descendants_but_preserves_their_tails(self):
        signal = self._h1_signal(
            '<h1>Visible <span hidden>forged hidden text</span> tail '
            '<span style="display:none">forged style text</span> end</h1>'
        )
        self.assertTrue(signal.ok, signal.detail)
        self.assertIn("Visible tail end", signal.detail)
        self.assertNotIn("forged", signal.detail)

    def test_multiple_jsonld_defects_emit_one_official_diagnostic_signal(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<script type="application/ld+json">{</script>'
            '<script type="application/ld+json">'
            '{"@context":"https://invalid.example/","@type":7}'
            '</script></head><body><h1>Visible heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            signals = core.check_home("https://example.com/")
        diagnostics = [
            signal for signal in signals if signal.key == "jsonld_valid"
        ]
        self.assertEqual(len(diagnostics), 1)
        self.assertFalse(diagnostics[0].ok)
        self.assertEqual(
            diagnostics[0].weight,
            core.SIGNAL_WEIGHT_CONTRACT["jsonld_valid"],
        )

    def test_current_public_home_page_retains_one_visible_h1(self):
        repository = Path(__file__).resolve().parents[3]
        html = (repository / "site" / "index.html").read_text(encoding="utf-8")
        with patch.object(core, "_get", return_value=(200, html)):
            signal = next(
                item for item in core.check_home("https://advisorsai.ai/")
                if item.key == "h1"
            )
        self.assertTrue(signal.ok, signal.detail)

    def test_canonical_uses_only_the_first_active_base_href_in_dom_order(self):
        passing_bases = (
            # The first active base wins; a later private value is inert.
            '<base href="/safe/"><base href="http://127.0.0.1/private/">',
            # HTML tokenization keeps the first duplicate attribute.
            '<base href="/safe/" href="http://127.0.0.1/private/">',
            # An empty href is effective and cannot be replaced by a later one.
            '<base href=""><base href="https://other.example.net/forged/">',
            # A relative, same-origin base is the actual resolution base.
            '<base href="../safe/">',
            # A base without href is not the first effective href-bearing base.
            '<base target="_blank"><base href="/safe/">',
        )
        for bases in passing_bases:
            html = (
                '<html><head>' + bases
                + '<link rel="canonical" href="page.html"></head>'
                '<body><h1>Visible heading</h1></body></html>'
            )
            with self.subTest(bases=bases), patch.object(
                    core, "_get", return_value=(200, html)):
                canonical = next(
                    signal for signal in core.check_home(
                        "https://example.com/root/index.html")
                    if signal.key == "canonical"
                )
            self.assertTrue(canonical.ok, (bases, canonical.detail))

        # html5lib 1.1 is the checker's fixed DOM contract.  Its tree builder
        # closes the effective head before this template; the following link
        # therefore lives in body and is not canonical evidence.
        template_in_head = (
            '<html><head><template><base href="http://127.0.0.1/private/">'
            '</template><link rel="canonical" href="page.html"></head>'
            '<body><h1>Visible heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, template_in_head)):
            canonical = next(
                signal for signal in core.check_home(
                    "https://example.com/root/index.html")
                if signal.key == "canonical"
            )
        self.assertFalse(canonical.ok, canonical.detail)

        outside_head = (
            '<html><head><link rel="canonical" href="page.html"></head>'
            '<body><base href="http://127.0.0.1/private/">'
            '<h1>Visible heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, outside_head)):
            canonical = next(
                signal for signal in core.check_home(
                    "https://example.com/root/index.html")
                if signal.key == "canonical"
            )
        self.assertFalse(canonical.ok, canonical.detail)

        safe_body_base = (
            '<html><head><link rel="canonical" href="page.html"></head>'
            '<body><base href="/safe/"><h1>Visible heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, safe_body_base)):
            canonical = next(
                signal for signal in core.check_home(
                    "https://example.com/root/index.html")
                if signal.key == "canonical"
            )
        self.assertTrue(canonical.ok, canonical.detail)

    def test_unsafe_first_active_base_invalidates_canonical_identity(self):
        rejected_bases = (
            'http://127.0.0.1/private/',
            'https://other.example.net/forged/',
            'https://bad_.example.net/forged/',
            'javascript:alert(1)',
        )
        for href in rejected_bases:
            html = (
                f'<html><head><base href="{href}">'
                '<base href="/later-safe/">'
                '<link rel="canonical" href="page.html"></head>'
                '<body><h1>Visible heading</h1></body></html>'
            )
            with self.subTest(href=href), patch.object(
                    core, "_get", return_value=(200, html)):
                canonical = next(
                    signal for signal in core.check_home(
                        "https://example.com/root/index.html")
                    if signal.key == "canonical"
                )
            self.assertFalse(canonical.ok, (href, canonical.detail))

    def test_html5_script_double_escaped_text_cannot_forge_active_elements(self):
        html = (
            '<script><!--<script></script><h1>Forged heading</h1>'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@graph":['
            '{"@type":"Organization","name":"Forged"},'
            '{"@type":"Service","name":"Forged"}]}'
            '</script></script>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        self.assertFalse(by_key["h1"].ok)
        self.assertFalse(by_key["structured_business"].ok)
        self.assertFalse(by_key["structured_offering"].ok)

    def test_markup_inside_comments_or_inert_elements_cannot_forge_page_basics(self):
        forged = """<!doctype html><html><head>
        <!-- <title>A sufficiently descriptive forged title</title>
        <meta name="description" content="A sufficiently long forged description that must not count for anything.">
        <script type="application/ld+json">{"@graph":[{"@type":"Organization","name":"Forged"},{"@type":"Service","name":"Forged"}]}</script>
        <link rel="canonical" href="https://example.com/forged">
        </head><body><h1>Forged heading</h1> -->
        <template><title>Template title must not count</title><h1>Template heading</h1><link rel="canonical" href="https://example.com/template"></template>
        </body></html>"""
        with patch.object(core, "_get", return_value=(200, forged)):
            signals = core.check_home("https://example.com/")
        by_key = {signal.key: signal for signal in signals}
        for key in (
            "title", "description", "structured_business",
            "structured_offering", "h1", "canonical",
        ):
            with self.subTest(key=key):
                self.assertFalse(by_key[key].ok)

    def test_every_rawtext_or_inert_context_blocks_forged_semantics(self):
        forged = (
            '<title>A sufficiently descriptive forged title</title>'
            '<meta name="description" content="A sufficiently long forged description that must never count for the public page.">'
            '<script type="application/ld+json">'
            '{"@graph":[{"@type":"Organization","name":"Forged"},'
            '{"@type":"Service","name":"Forged"}]}</script>'
            '<link rel="canonical" href="https://public.example.net/forged">'
            '<h1>Forged heading</h1>'
        )
        for tag in (
            "iframe", "textarea", "plaintext", "template", "noscript",
            "script", "style", "xmp", "noembed", "noframes",
        ):
            payload = forged
            if tag == "script":
                payload = re.sub(
                    r'<script type="application/ld\+json">.*?</script>', "",
                    payload,
                )
            closing = "" if tag == "plaintext" else f"</{tag}>"
            html = f"<!doctype html><html><body><{tag}>{payload}{closing}</body></html>"
            with self.subTest(tag=tag), patch.object(
                    core, "_get", return_value=(200, html)):
                by_key = {
                    signal.key: signal
                    for signal in core.check_home("https://example.com/")
                }
            for key in (
                "title", "description", "structured_business",
                "structured_offering", "h1", "canonical",
            ):
                self.assertFalse(by_key[key].ok, (tag, key, by_key[key]))

    def test_mismatched_close_and_nonvoid_self_close_cannot_escape_inert_stack(self):
        documents = (
            # A mismatched raw-text end tag used to decrement a shared counter.
            "<template></script><h1>Forged</h1></template>",
            "<iframe></style><h1>Forged</h1></iframe>",
            # Closing the outer template while a raw-text child is open is text,
            # not an escape from the template.
            "<template><noscript></template></noscript><h1>Forged</h1>",
            # Browsers ignore the self-closing slash on non-void HTML elements.
            "<template/><h1>Forged</h1>",
            # plaintext never recognises even its own apparent closing tag.
            "<plaintext></plaintext><h1>Forged</h1>",
        )
        for fragment in documents:
            html = f"<!doctype html><html><body>{fragment}</body></html>"
            with self.subTest(fragment=fragment), patch.object(
                    core, "_get", return_value=(200, html)):
                signals = core.check_home("https://example.com/")
            h1 = next(signal for signal in signals if signal.key == "h1")
            self.assertFalse(h1.ok, fragment)

    def test_title_rcdata_cannot_emit_markup_or_body_evidence(self):
        html = (
            "<!doctype html><html><head><title>Short "
            "<h1>Forged heading</h1>"
            '<meta name="description" content="A forged description long enough to pass the old parser and mislead readers.">'
            '<link rel="canonical" href="https://public.example.net/forged">'
            "</title></head><body></body></html>"
        )
        with patch.object(core, "_get", return_value=(200, html)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        self.assertFalse(by_key["description"].ok)
        self.assertFalse(by_key["canonical"].ok)
        self.assertFalse(by_key["h1"].ok)

    def test_head_and_body_evidence_must_be_in_effective_html_regions(self):
        offering = (
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Service",'
            '"name":"Forged offer"}</script>'
        )
        forged = (
            "<!doctype html><html><head>" + offering + "<h1>Head heading</h1>"
            "</head><body>"
            "<title>A sufficiently descriptive body-forged title</title>"
            '<meta name="description" content="A body-forged description long enough to pass a location-blind parser.">'
            '<link rel="canonical" href="https://public.example.net/forged">'
            "</body></html>"
        )
        with patch.object(core, "_get", return_value=(200, forged)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        for key in ("title", "description", "canonical"):
            self.assertFalse(by_key[key].ok, (key, by_key[key]))
        self.assertTrue(by_key["structured_offering"].ok)
        # HTML5 closes the head when a body element is encountered.  The h1 is
        # therefore effective body content even though its source precedes the
        # literal closing head tag.
        self.assertTrue(by_key["h1"].ok)

    def test_foreign_content_follows_html5_dom_then_pure_html_policy(self):
        payload = (
            "<title>A sufficiently descriptive foreign title</title>"
            '<meta name="description" content="A foreign description long enough to pass a namespace-blind parser.">'
            '<link rel="canonical" href="https://public.example.net/forged">'
            '<script type="application/ld+json">'
            '{"@graph":[{"@type":"Organization","name":"Forged"},'
            '{"@type":"Service","name":"Forged"}]}</script>'
            "<h1>Foreign heading</h1>"
        )
        for fragment, h1_expected in (
            # h1 is one of the HTML start tags that exits foreign-content
            # parsing, so html5lib places it as active body HTML.
            (f"<svg>{payload}</svg>", True),
            # foreignObject is an integration point: its children use the HTML
            # namespace, but this checker deliberately rejects evidence with a
            # foreign ancestor.
            (f"<svg><foreignObject>{payload}</foreignObject></svg>", False),
            (f"<math>{payload}</math>", True),
        ):
            html = f"<!doctype html><html><body>{fragment}</body></html>"
            with self.subTest(fragment=fragment[:30]), patch.object(
                    core, "_get", return_value=(200, html)):
                by_key = {
                    signal.key: signal
                    for signal in core.check_home("https://example.com/")
                }
            for key in (
                "title", "description", "structured_business",
                "structured_offering", "canonical",
            ):
                self.assertFalse(by_key[key].ok, (key, by_key[key]))
            self.assertIs(by_key["h1"].ok, h1_expected, by_key["h1"])

    def test_html5lib_dom_contract_handles_eof_noscript_select_and_script(self):
        cases = {
            "select": ("<select><h1>Forged</h1></select><h1>Real</h1>", 1),
            "noscript": ("<noscript><h1>Forged</h1></noscript><h1>Real</h1>", 1),
            "eof-h1": ("<h1>Real at EOF", 1),
            "double-script": (
                "<script><!--<script></script><h1>Forged</h1></script></script>"
                "<h1>Real</h1>",
                1,
            ),
        }
        for label, (markup, count) in cases.items():
            with self.subTest(label=label):
                document = core._parse_page_document(markup)
                self.assertEqual(document.h1_element_count, count)
                self.assertEqual(document.h1_values, ["Real" if label != "eof-h1" else "Real at EOF"])

        eof_jsonld = core._parse_page_document(
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Service",'
            '"name":"EOF offer"}'
        )
        self.assertEqual(len(eof_jsonld.json_ld_blocks), 1)
        self.assertIn("EOF offer", eof_jsonld.json_ld_blocks[0][0])

    def test_canonical_requires_a_nonempty_valid_href(self):
        shell = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            '{}'
            '</head><body><h1>One heading</h1></body></html>'
        )
        for tag in ('<link rel="canonical">', '<link rel="canonical" href="">',
                    '<link rel="canonical" href="javascript:alert(1)">'):
            with self.subTest(tag=tag), patch.object(
                    core, "_get", return_value=(200, shell.format(tag))):
                signals = core.check_home("https://example.com/")
                canonical = next(s for s in signals if s.key == "canonical")
                self.assertFalse(canonical.ok)

        multiple = shell.format(
            '<link rel="canonical" href="https://example.com/one">'
            '<link rel="canonical" href="https://example.com/two">'
        )
        with patch.object(core, "_get", return_value=(200, multiple)):
            canonical = next(
                signal for signal in core.check_home("https://example.com/")
                if signal.key == "canonical"
            )
        self.assertFalse(canonical.ok)

    def test_canonical_rejects_local_private_and_link_local_targets(self):
        shell = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            '{}'
            '</head><body><h1>One heading</h1></body></html>'
        )
        blocked = (
            "http://localhost/private", "http://api.localhost/private",
            "http://localhost.localdomain/private", "http://127.0.0.1/private",
            "http://127.1/private", "http://10.0.0.7/private",
            "http://172.16.0.7/private", "http://192.168.1.7/private",
            "http://169.254.169.254/latest/meta-data", "http://[::1]/private",
            "http://[fe80::1]/private", "http://2130706433/private",
            "http://0x7f000001/private", "http://0x7f.0.0.1/private",
            "http://0x7f.1/private", "http://0x7f.0x0.1/private",
            "http://0177.0.0.1/private",
        )
        for href in blocked:
            tag = f'<link rel="canonical" href="{href}">'
            with self.subTest(href=href), patch.object(
                    core, "_get", return_value=(200, shell.format(tag))):
                signals = core.check_home("https://example.com/")
            canonical = next(s for s in signals if s.key == "canonical")
            self.assertFalse(canonical.ok, href)

    def test_canonical_rejects_encoded_authorities_and_invalid_dns_labels(self):
        shell = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            '{}'
            '</head><body><h1>One heading</h1></body></html>'
        )
        long_label = "a" * 64
        blocked = (
            "https://example%2ecom/path",
            "https://example.com%2f.evil.test/path",
            "https://example%00.com/path",
            "https://example_com/path",
            "https://-bad.example/path",
            "https://bad-.example/path",
            "https://bad..example/path",
            "https://.example/path",
            "https://example.com./path",
            "https://router.home.arpa/path",
            f"https://{long_label}.example/path",
            "https://ｅxample.com/path",
            "https://example。com/path",
            "https://xn--.example/path",
            "https://xn--not-valid-.example/path",
            "https://public.example.net/%2fadmin",
            "https://public.example.net/%00admin",
            "https://public.example.net/\x7fadmin",
        )
        for href in blocked:
            with self.subTest(href=href), patch.object(
                    core, "_get", return_value=(
                        200, shell.format(
                            f'<link rel="canonical" href="{href}">'))):
                canonical = next(
                    signal for signal in core.check_home("https://example.com/")
                    if signal.key == "canonical"
                )
            self.assertFalse(canonical.ok, href)

    def test_canonical_rejects_a_public_cross_domain_target(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            '<link rel="canonical" href="https://public.example.net/new-home">'
            '</head><body><h1>One heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            signals = core.check_home("https://example.com/")
        canonical = next(s for s in signals if s.key == "canonical")
        self.assertFalse(canonical.ok)

    def test_home_requires_html_media_type_end_to_end(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '</head><body><h1>One heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=core._FetchDocument(
                200, html, "text/plain; charset=utf-8")):
            signals = core.check_home("https://example.com/")
        self.assertEqual(
            {signal.key for signal in signals},
            {
                "home", "title", "description", "structured_business",
                "structured_offering", "h1", "canonical",
            },
        )
        self.assertTrue(all(signal.ok is False for signal in signals))

    def test_semantic_text_requires_letters_or_numbers_and_rejects_unsafe_scalars(self):
        for value in (
            "\u0301", "\ufe0f", "safe\ue000", "safe\u0378",
            "safe\x01", "safe\u200b", "safe\u202e",
        ):
            with self.subTest(value=ascii(value)):
                self.assertEqual(core._meaningful_visible_text(value), "")
        self.assertEqual(core._meaningful_visible_text(" １２٣ Name "), "12٣ Name")
        self.assertEqual(core._meaningful_visible_text("\ud800"), "")

    def test_title_description_h1_and_jsonld_name_share_visible_text_policy(self):
        unsafe = "Safe\u200bName"
        html = (
            f'<html><head><title>{unsafe}</title>'
            f'<meta name="description" content="{unsafe} with enough words '
            'to exceed the ordinary minimum description length safely">'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Organization",'
            f'"name":"{unsafe}"}}'
            f'</script></head><body><h1>{unsafe}</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        for key in ("title", "description", "h1", "structured_business"):
            with self.subTest(key=key):
                self.assertFalse(by_key[key].ok)

    def test_non_finite_jsonld_numbers_are_invalid_json(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            html = (
                '<html><head><title>A sufficiently descriptive page title</title>'
                '<script type="application/ld+json">'
                '{"@context":"https://schema.org","@type":"Organization",'
                f'"name":"Business","value":{constant}}}'
                '</script></head><body><h1>One heading</h1></body></html>'
            )
            with self.subTest(constant=constant), patch.object(
                    core, "_get", return_value=(200, html)):
                by_key = {
                    signal.key: signal
                    for signal in core.check_home("https://example.com/")
                }
            self.assertFalse(by_key["jsonld_valid"].ok)
            self.assertFalse(by_key["structured_business"].ok)

    def test_parser_child_accepts_valid_sibling_rawtext_and_plain_documents(self):
        cases = (
            ("<p>paragraph" * 129 + "<h1>Real</h1>", 1),
            ("<script>" + "<div>token</div>" * 5_000
             + "</script><h1>Real</h1>", 1),
            ("<p>one</p>" * 2_049 + "<h1>Real</h1>", 1),
            ("x" * 140_000, 0),
        )
        for source, expected_h1 in cases:
            started = time.perf_counter()
            with self.subTest(length=len(source)):
                document = core._parse_page_document(source)
            self.assertEqual(document.h1_element_count, expected_h1)
            self.assertLess(time.perf_counter() - started, 2.0)

    def test_parser_child_rejects_deep_dom_quickly_and_is_reaped(self):
        processes = []
        real_popen = core.subprocess.Popen

        def recording_popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        started = time.perf_counter()
        with patch.object(core.subprocess, "Popen", side_effect=recording_popen), \
                self.assertRaises(ValueError):
            core._parse_page_document(
                "<div>" * 5_000 + "</div>" * 5_000)
        self.assertLess(
            time.perf_counter() - started, core.HTML_PARSE_TIMEOUT + 0.75)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_parser_hard_timeout_kills_and_reaps_the_child(self):
        processes = []
        real_popen = core.subprocess.Popen

        def slow_popen(_args, **kwargs):
            process = real_popen(
                [sys.executable, "-c", "import time;time.sleep(60)"],
                **kwargs,
            )
            processes.append(process)
            return process

        started = time.perf_counter()
        with (
            patch.object(core, "HTML_PARSE_TIMEOUT", 0.05),
            patch.object(core.subprocess, "Popen", side_effect=slow_popen),
            self.assertRaisesRegex(ValueError, "deadline"),
        ):
            core._parse_page_document("<h1>safe input</h1>")
        self.assertLess(time.perf_counter() - started, 1.0)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_xhtml_media_type_is_rejected_without_promoting_malformed_signals(self):
        malformed = (
            "<html><head><title>A title long enough</title>"
            "<meta name='description' content='A description long enough to "
            "look valid to a permissive HTML parser but malformed as XML.'>"
            "</head><body><h1>Forged</h1></body></html>"
        )
        with patch.object(core, "_get", return_value=core._FetchDocument(
                200, malformed, "application/xhtml+xml; charset=utf-8")):
            signals = core.check_home("https://example.com/")
        self.assertEqual(
            {signal.key for signal in signals},
            {
                "home", "title", "description", "structured_business",
                "structured_offering", "h1", "canonical",
            },
        )
        self.assertTrue(all(signal.ok is False for signal in signals))
        self.assertIn("text/html", signals[0].detail)

    def test_html_200_is_not_a_sitemap(self):
        with patch.object(core, "_get", return_value=(200, "<html>not xml sitemap</html>")):
            signal = core.check_sitemap("https://example.com/")[0]
        self.assertFalse(signal.ok)

    def test_sitemap_requires_exact_09_namespace_and_xml_media_type(self):
        body = (
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>https://example.com/a</loc></url></urlset>'
        )
        for content_type, expected in (
            ("application/xml; charset=utf-8", True),
            ("text/xml", True),
            ("text/plain", False),
        ):
            with self.subTest(content_type=content_type), patch.object(
                    core, "_get", return_value=core._FetchDocument(
                        200, body, content_type)):
                self.assertIs(core.check_sitemap(
                    "https://example.com/")[0].ok, expected)
        unnamespaced = (
            '<urlset><url><loc>https://example.com/a</loc></url></urlset>'
        )
        with patch.object(core, "_get", return_value=(200, unnamespaced)):
            self.assertFalse(core.check_sitemap(
                "https://example.com/")[0].ok)

    def test_sitemap_with_doctype_or_entity_is_rejected_before_xml_parse(self):
        body = '<!DOCTYPE urlset [<!ENTITY x "https://example.com/">]><urlset><url><loc>&x;</loc></url></urlset>'
        with (
            patch.object(core, "_get", return_value=(200, body)),
            patch.object(core.ET, "fromstring") as parse,
        ):
            signal = core.check_sitemap("https://example.com/")[0]
        self.assertFalse(signal.ok)
        parse.assert_not_called()

    def test_valid_urlset_requires_a_nonempty_location(self):
        empty = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc/></url></urlset>'
        valid = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/a</loc></url></urlset>'
        with patch.object(core, "_get", return_value=(200, empty)):
            self.assertFalse(core.check_sitemap("https://example.com/")[0].ok)
        with patch.object(core, "_get", return_value=(200, valid)):
            self.assertTrue(core.check_sitemap("https://example.com/")[0].ok)

    def test_mutation_sitemap_requires_expected_records_and_http_locations(self):
        invalid_documents = (
            "<urlset><loc>https://example.com/a</loc></urlset>",
            "<urlset><other><loc>https://example.com/a</loc></other></urlset>",
            "<urlset><url><loc>javascript:alert(1)</loc></url></urlset>",
            "<urlset><url><loc>/relative</loc></url></urlset>",
            "<URLSET><URL><LOC>https://example.com/a</LOC></URL></URLSET>",
            "<urlset><url><loc>https://example.com/%ZZ</loc></url></urlset>",
            "<urlset><url><loc>https://example.com\\admin</loc></url></urlset>",
            "<sitemapindex><url><loc>https://example.com/a</loc></url></sitemapindex>",
            (
                "<urlset><url><loc>https://example.com/a</loc></url>"
                "<url><loc>ftp://example.com/b</loc></url></urlset>"
            ),
        )
        for body in invalid_documents:
            with self.subTest(body=body), patch.object(
                    core, "_get", return_value=(200, body)):
                self.assertFalse(
                    core.check_sitemap("https://example.com/")[0].ok)

        valid_index = (
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<sitemap><loc>https://example.com/pages.xml</loc></sitemap>"
            "</sitemapindex>"
        )
        with patch.object(core, "_get", return_value=(200, valid_index)):
            signal = core.check_sitemap("https://example.com/")[0]
        self.assertTrue(signal.ok)
        self.assertIn("1 location", signal.detail)

    def test_sitemap_locations_are_public_and_same_site(self):
        template = (
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            '<url><loc>{}</loc></url></urlset>'
        )
        blocked = (
            "http://127.0.0.1/private",
            "http://0x7f.1/private",
            "http://router.local/admin",
            "https://bad_.example/path",
            "https://other-controller.example.net/path",
        )
        for location in blocked:
            with self.subTest(location=location), patch.object(
                    core, "_get", return_value=(200, template.format(location))):
                signal = core.check_sitemap("https://example.com/")[0]
            self.assertFalse(signal.ok, location)

    def test_jsonld_requires_an_exact_schema_org_context(self):
        shell = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page '
            'description for machine readers and buyers."></head><body>'
            '<h1>One heading</h1><script type="application/ld+json">{}</script>'
            '</body></html>'
        )
        payloads = (
            {"@type": "Organization", "name": "Missing context"},
            {
                "@context": {
                    "Organization": "https://attacker.invalid/Thing",
                    "Service": "https://attacker.invalid/Offer",
                },
                "@graph": [
                    {"@type": "Organization", "name": "Forged"},
                    {"@type": "Service", "name": "Forged"},
                ],
            },
        )
        for payload in payloads:
            with self.subTest(payload=payload), patch.object(
                    core, "_get", return_value=(
                        200, shell.format(json.dumps(payload)))):
                by_key = {
                    signal.key: signal
                    for signal in core.check_home("https://example.com/")
                }
            self.assertFalse(by_key["structured_business"].ok)
            self.assertFalse(by_key["structured_offering"].ok)
            self.assertFalse(by_key["jsonld_valid"].ok)

    def test_structured_types_without_names_do_not_pass(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@graph":['
            '{"@type":"Organization"},{"@type":"Service","name":"   "}]}'
            '</script></head><body><h1>One heading</h1></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            signals = core.check_home("https://example.com/")
        by_key = {signal.key: signal for signal in signals}
        self.assertFalse(by_key["structured_business"].ok)
        self.assertFalse(by_key["structured_offering"].ok)

    def test_jsonld_names_reject_controls_zero_width_and_bidi_formatting(self):
        for unsafe_name in (
            "\u0000", "\u200b", "\u2060", "\u202e",
            "Visible\u0000name", "Visible\u200bname",
            "Visible\u2060name", "Visible\u202ename",
        ):
            payload = {
                "@context": "https://schema.org",
                "@graph": [
                    {"@type": "Organization", "name": unsafe_name},
                    {"@type": "Service", "name": unsafe_name},
                ],
            }
            html = (
                '<html><head><title>A sufficiently descriptive page title</title>'
                '<script type="application/ld+json">'
                + json.dumps(payload)
                + '</script></head><body><h1>One heading</h1></body></html>'
            )
            with self.subTest(name=repr(unsafe_name)), patch.object(
                    core, "_get", return_value=(200, html)):
                by_key = {
                    signal.key: signal
                    for signal in core.check_home("https://example.com/")
                }
            self.assertFalse(by_key["structured_business"].ok)
            self.assertFalse(by_key["structured_offering"].ok)

        self.assertTrue(core._safe_visible_jsonld_name("A visible offer"))

        literal_nul = (
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Service",'
            '"name":"Unsafe\x00offer"}</script><h1>One heading</h1>'
        )
        with patch.object(core, "_get", return_value=(200, literal_nul)):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        self.assertFalse(by_key["structured_offering"].ok)

    def test_mutation_jsonld_name_guard_is_on_the_scoring_path(self):
        html = (
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"Service",'
            '"name":"\\u200b"}</script><h1>One heading</h1>'
        )
        with patch.object(core, "_get", return_value=(200, html)), \
                patch.object(core, "_safe_visible_jsonld_name", return_value=True):
            by_key = {
                signal.key: signal
                for signal in core.check_home("https://example.com/")
            }
        # This deliberately mutated guard makes the forged node score.  If the
        # production test stopped exercising that guard, this proof would fail.
        self.assertTrue(by_key["structured_offering"].ok)

    def test_mutation_non_text_jsonld_type_is_ignored_without_aborting_home(self):
        invalid_types = ({"name": "Organization"}, 7, [["Service"]])
        for invalid_type in invalid_types:
            data = {
                "@context": "https://schema.org",
                "@graph": [
                    {"@type": invalid_type, "name": "Forged business"},
                ]
            }
            html = (
                "<html><head><title>A sufficiently descriptive page title</title>"
                '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
                '<script type="application/ld+json">'
                + json.dumps(data)
                + "</script></head><body><h1>One heading</h1></body></html>"
            )
            with self.subTest(invalid_type=invalid_type), patch.object(
                    core, "_get", return_value=(200, html)):
                signals = core.check_home("https://example.com/")
            by_key = {signal.key: signal for signal in signals}
            self.assertFalse(by_key["jsonld_valid"].ok)
            self.assertFalse(by_key["structured_business"].ok)
            self.assertFalse(by_key["structured_offering"].ok)

    def test_unicode_whitespace_cannot_canonicalize_jsonld_payload_or_type(self):
        payloads = (
            '\u00a0{"@context":"https://schema.org","@type":'
            '"Organization","name":"Forged"}\u00a0',
            '{"@context":"https://schema.org","@graph":['
            '{"@type":"Organization\u00a0","name":"Forged"},'
            '{"@type":"Service\u00a0","name":"Forged"}]}',
        )
        shell = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page '
            'description for machine readers and buyers.">'
            '<script type="application/ld+json">{}</script></head>'
            '<body><h1>One heading</h1></body></html>'
        )
        for payload in payloads:
            with self.subTest(payload=payload), patch.object(
                    core, "_get", return_value=(200, shell.format(payload))):
                by_key = {
                    signal.key: signal
                    for signal in core.check_home("https://example.com/")
                }
            self.assertFalse(by_key["structured_business"].ok)
            self.assertFalse(by_key["structured_offering"].ok)

    def test_mutation_h1_inside_noncontent_elements_is_not_counted(self):
        html = (
            "<html><head><title>A sufficiently descriptive page title</title>"
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            "<script>const sample = '<h1>Script heading</h1>';</script>"
            "<style>.demo::after { content: '<h1>Style heading</h1>'; }</style>"
            "<template><h1>Template heading</h1></template>"
            "</head><body><h1>Visible heading</h1></body></html>"
        )
        with patch.object(core, "_get", return_value=(200, html)):
            signals = core.check_home("https://example.com/")
        h1 = next(signal for signal in signals if signal.key == "h1")
        self.assertTrue(h1.ok)
        self.assertIn("Visible heading", h1.detail)
        self.assertNotIn("Script heading", h1.detail)

    def test_nested_or_implicitly_closed_h1_cannot_look_like_one_heading(self):
        html = (
            "<html><head><title>A sufficiently descriptive page title</title>"
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            "</head><body><h1>First<h1>Second</h1></h1></body></html>"
        )
        with patch.object(core, "_get", return_value=(200, html)):
            h1 = next(
                signal for signal in core.check_home("https://example.com/")
                if signal.key == "h1"
            )
        self.assertFalse(h1.ok)

    def test_named_business_and_service_nodes_pass(self):
        html = (
            '<html><head><title>A sufficiently descriptive page title</title>'
            '<meta name="description" content="A sufficiently long page description for machine readers and buyers.">'
            '</head><body><h1>One heading</h1>'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@graph":['
            '{"@type":"Organization","name":"Example"},'
            '{"@type":"Service","name":"Readiness audit"}]}'
            '</script></body></html>'
        )
        with patch.object(core, "_get", return_value=(200, html)):
            signals = core.check_home("https://example.com/")
        by_key = {signal.key: signal for signal in signals}
        self.assertTrue(by_key["structured_business"].ok)
        self.assertTrue(by_key["structured_offering"].ok)

    def test_cli_does_not_relabel_page_basics_as_crawler_or_visibility_proof(self):
        report = core.Report(url="https://example.com/")
        report.signals.append(core.Signal("title", True, "title present", 1))
        report.signals.append(core.Signal("llms_txt", False, "no experimental summary", 0))
        rendered = cli.render(report)
        self.assertIn("bounded fetch of declared page", rendered)
        self.assertIn("not: proof that an official crawler", rendered)
        self.assertIn("note no experimental summary", rendered)
        self.assertNotIn("MISS no experimental summary", rendered)
        self.assertNotIn("whether machines can READ you", rendered)

    def test_mutation_report_errors_make_result_and_cli_unsuccessful(self):
        report = core.Report(
            url="https://example.com/",
            signals=[
                core.Signal(key, True, f"{key} receipt", weight)
                for key, weight in core.SIGNAL_WEIGHT_CONTRACT.items()
                if key in core.REQUIRED_SIGNAL_KEYS
            ],
        )
        report.errors.append("check_home: RuntimeError")
        self.assertIsNone(report.score)
        self.assertFalse(report.successful)
        self.assertEqual(report.coverage_percent, 92)

        output = io.StringIO()
        with (
            patch.object(cli, "run", return_value=report),
            contextlib.redirect_stdout(output),
        ):
            exit_code = cli.main(["example.com", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["success"])
        self.assertEqual(payload["errors"], ["check_home: RuntimeError"])
        self.assertIsNone(payload["score"])
        self.assertEqual(payload["coverage_percent"], 92)

    def test_total_deadline_leaves_no_workers_and_keeps_completed_checks(self):
        def slow_until_deadline(_base: str, *, deadline=None):
            target = min(time.monotonic() + 0.8, float(deadline))
            while time.monotonic() < target:
                time.sleep(0.002)
            raise TimeoutError("simulated slow endpoint")

        fast_signal = core.Signal("home", True, "fast home", 0)
        with (
            patch.object(core, "TIMEOUT", 0.05),
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "check_home", new=slow_until_deadline),
        ):
            started = time.perf_counter()
            report = core.run("https://example.com/")
        self.assertLess(time.perf_counter() - started, 0.3)
        self.assertEqual(len(report.errors), 4)
        self.assertFalse(any(
            thread.name.startswith("readability")
            for thread in __import__("threading").enumerate()
        ))

        with (
            patch.object(core, "TIMEOUT", 0.05),
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "check_home", return_value=[fast_signal]),
            patch.object(core, "check_robots", new=slow_until_deadline),
        ):
            report = core.run("https://example.com/")
        self.assertEqual(
            {signal.key for signal in report.signals},
            {"home", "robots", "llms_txt", "sitemap"},
        )
        self.assertEqual(report.signals[0], fast_signal)
        self.assertEqual(len(report.errors), 3)
        self.assertFalse(any(
            thread.name.startswith("readability")
            for thread in __import__("threading").enumerate()
        ))

    def test_mutation_unchecked_signal_is_partial_nonzero_and_never_score_100(self):
        report = core.Report(
            url="https://example.com/",
            signals=[
                core.Signal(
                    key,
                    None if key == "h1" else True,
                    "page unavailable" if key == "h1" else f"{key} receipt",
                    weight,
                )
                for key, weight in core.SIGNAL_WEIGHT_CONTRACT.items()
                if key in core.REQUIRED_SIGNAL_KEYS
            ],
        )
        self.assertFalse(report.successful)
        self.assertIsNone(report.score)
        self.assertEqual(report.coverage_percent, 91)

        output = io.StringIO()
        with (
            patch.object(cli, "run", return_value=report),
            contextlib.redirect_stdout(output),
        ):
            exit_code = cli.main(["example.com", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["success"])
        self.assertIsNone(payload["score"])
        self.assertEqual(payload["coverage_percent"], 91)
        self.assertEqual(payload["unchecked_count"], 1)

        def broken_home(_base: str, *, deadline=None):
            _ = deadline
            raise RuntimeError("injected checker failure")

        with (
            patch.object(core, "_resolve_public", return_value=["93.184.216.34"]),
            patch.object(core, "_get", return_value=(404, "")),
            patch.object(core, "check_home", new=broken_home),
        ):
            actual = core.run("https://example.com/")
        self.assertFalse(actual.successful)
        self.assertEqual(actual.errors, ["broken_home: RuntimeError"])

    def test_mutation_cli_strips_ansi_osc_and_controls_from_untrusted_fields(self):
        report = core.Report(url="https://example.com/")
        report.signals.extend([
            core.Signal(
                "title", False,
                "page title: \x1b[31mred\x1b[0m \x1b]0;owned-title\x07 end\x00",
                1),
            core.Signal(
                "h1", False,
                "one <h1>: \x1b]8;;https://evil.invalid\x1b\\owned-link\x1b]8;;\x1b\\\u202e",
                1),
        ])
        report.errors.append(
            "check_home: \x1b[2J\x1b]52;c;clipboard-payload\x07RuntimeError\x7f")

        with patch.object(cli, "_plain", return_value=True):
            rendered = cli.render(report)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x00", rendered)
        self.assertNotIn("\x07", rendered)
        self.assertNotIn("\x7f", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertNotIn("owned-title", rendered)
        self.assertNotIn("https://evil.invalid", rendered)
        self.assertIn("owned-link", rendered)
        self.assertNotIn("clipboard-payload", rendered)
        self.assertIn("RESULT INCOMPLETE", rendered)

        output = io.StringIO()
        with (
            patch.object(cli, "run", return_value=report),
            contextlib.redirect_stdout(output),
        ):
            exit_code = cli.main(["example.com", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        serialised = json.dumps(payload)
        self.assertNotIn("\\u001b", serialised)
        self.assertNotIn("\\u202e", serialised)
        self.assertNotIn("owned-title", serialised)
        self.assertNotIn("https://evil.invalid", serialised)
        self.assertIn("owned-link", serialised)
        self.assertNotIn("clipboard-payload", serialised)

    def test_mutation_cli_sanitises_rejected_address_error(self):
        error = ValueError("bad \x1b]0;owned-error\x07 address\x00")
        stderr = io.StringIO()
        with (
            patch.object(cli, "run", side_effect=error),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = cli.main(["example.com"])
        self.assertEqual(exit_code, 2)
        self.assertNotIn("\x1b", stderr.getvalue())
        self.assertNotIn("owned-error", stderr.getvalue())
        self.assertNotIn("\x00", stderr.getvalue())

    def test_distribution_copy_does_not_claim_assistants_can_read_the_page(self):
        package_root = Path(__file__).resolve().parents[1]
        pyproject = (package_root / "pyproject.toml").read_text(encoding="utf-8")
        readme = (package_root / "README.md").read_text(encoding="utf-8")
        combined = (pyproject + "\n" + readme).lower()
        self.assertNotIn("assistants can actually read", combined)
        self.assertNotIn("can the ai assistants", combined)
        self.assertIn("bounded machine-readable public-page basics", pyproject)


if __name__ == "__main__":
    unittest.main()
