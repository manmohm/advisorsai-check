"""Bounded machine-readable page basics for a public website.

WHAT THIS MEASURES, EXACTLY
    Whether the submitted public page exposes a small set of declared,
    machine-readable basics: search-crawler policy for that path, page
    metadata, structured business/offering names, and a valid sitemap.

    This does not prove that an official crawler passes a firewall or bot
    challenge.  The fetch is made by this checker, not by those crawlers.

WHAT THIS DOES NOT MEASURE — and no free tool can
    Whether an AI assistant actually names you when a buyer asks. That is not
    a property of your HTML; it is an observation of a live answer, and it
    takes real captures against real assistants to establish. Anyone selling a
    number for it from a page fetch is selling a guess.

    So every result here is a PAGE-BASICS signal: a fixable technical
    condition, not evidence that an answer engine will cite the site. It is
    not a ranking, a share, or a promise, and this module never prints it as
    one.

No API keys. No account. Bounded HTTP fetches, nothing written back.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import unicodedata
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    import html5lib
except ModuleNotFoundError as exc:  # pragma: no cover - packaging failure path
    raise RuntimeError(
        "advisorsai-check requires html5lib==1.1; reinstall the package"
    ) from exc
if getattr(html5lib, "__version__", None) != "1.1":
    raise RuntimeError(
        "advisorsai-check requires html5lib==1.1; reinstall the package"
    )
try:
    import webencodings
except ModuleNotFoundError as exc:  # pragma: no cover - packaging failure path
    raise RuntimeError(
        "advisorsai-check requires webencodings==0.6.1; reinstall the package"
    ) from exc
if getattr(webencodings, "VERSION", None) != "0.6.1":
    raise RuntimeError(
        "advisorsai-check requires webencodings==0.6.1; reinstall the package"
    )

USER_AGENT = "advisorsai-check/1.0 (+https://advisorsai.ai)"
TIMEOUT = 5
MAX_BODY_BYTES = 2_000_000
MAX_REDIRECTS = 2
MAX_URL_CHARS = 2048
MAX_HTML_BYTES = 512_000
MAX_HTML_FACT_BYTES = 256_000
MAX_HTML_DOM_DEPTH = 4_096
# Windows spawn can exceed a sub-second slice while other isolated checkers
# are active.  Direct parser calls get enough startup headroom, while a real
# check remains bounded by the request's stricter absolute TIMEOUT.
HTML_PARSE_TIMEOUT = 10.0
HTTP_READ_CHUNK = 64 * 1024

_deadline_state = threading.local()

# Two kinds of AI crawler, and the difference decides the verdict.
#
# ANSWER-ENGINE crawlers support search or user-requested retrieval. Blocking
# one can prevent discovery or retrieval, so it fails this bounded check.
SEARCH_CRAWLERS = (
    "OAI-SearchBot", "Claude-SearchBot", "PerplexityBot",
    "Googlebot", "Bingbot",
)
# User-triggered fetchers do not represent autonomous indexing.  Their
# declared policy is reported as context but never changes the score.
USER_FETCHERS = (
    "ChatGPT-User", "Claude-User", "Perplexity-User",
)
ANSWER_CRAWLERS = SEARCH_CRAWLERS                       # import compatibility
# MODEL-USE crawlers are controlled separately from ordinary search. Blocking
# them can be a deliberate training/model-use policy, so it is reported as a
# note and never failed by a machine-readability check.
SCRAPE_CRAWLERS = (
    "GPTBot", "ClaudeBot", "Google-Extended",       # training / model-use controls
    "Applebot-Extended", "CCBot", "Bytespider",
    "meta-externalagent",
)
AI_CRAWLERS = SEARCH_CRAWLERS + USER_FETCHERS + SCRAPE_CRAWLERS

# One closed, versioned signal vocabulary.  The zero-weight rows are stage
# receipts: they prove the page and optional llms.txt stages ran, but never
# influence the score.  ``jsonld_valid`` is an optional diagnostic emitted
# only when malformed JSON-LD exists; every other row is required exactly once.
SIGNAL_WEIGHT_CONTRACT = MappingProxyType({
    "home": 0,
    "title": 1,
    "description": 1,
    "structured_business": 2,
    "structured_offering": 2,
    "h1": 1,
    "canonical": 1,
    "robots": 2,
    "llms_txt": 0,
    "sitemap": 1,
    "jsonld_valid": 1,
})
OPTIONAL_SIGNAL_KEYS = frozenset({"jsonld_valid"})
REQUIRED_SIGNAL_KEYS = frozenset(SIGNAL_WEIGHT_CONTRACT) - OPTIONAL_SIGNAL_KEYS
_PAGE_DERIVED_SIGNAL_KEYS = frozenset({
    "title",
    "description",
    "structured_business",
    "structured_offering",
    "h1",
    "canonical",
})


@dataclass
class Signal:
    """One checked fact. `ok` is None when the check could not be run."""
    key: str
    ok: bool | None
    detail: str
    weight: int = 1
    evidence: str = ""


def _signal_contract_facts(
        signals: list[Signal], errors: list[str] | None = None
) -> tuple[bool, int, int]:
    """Return ``(complete, checked_weight, coverage_denominator)``.

    Unknown, duplicate, malformed, or wrong-weight rows are never allowed to
    expand the trusted scoring vocabulary.  Each contract defect adds a
    missing-coverage unit, including missing zero-weight stage receipts, so a
    malformed report can never display 100% coverage.
    """
    seen: dict[str, Signal] = {}
    defects = 0
    for signal in signals:
        key = getattr(signal, "key", None)
        weight = getattr(signal, "weight", None)
        ok = getattr(signal, "ok", None)
        detail = getattr(signal, "detail", None)
        evidence = getattr(signal, "evidence", None)
        if (
            not isinstance(key, str)
            or key not in SIGNAL_WEIGHT_CONTRACT
            or type(weight) is not int
            or weight != SIGNAL_WEIGHT_CONTRACT.get(key)
            or (ok is not None and type(ok) is not bool)
            or not isinstance(detail, str)
            or not detail.strip()
            or not isinstance(evidence, str)
            or key in seen
        ):
            defects += 1
            continue
        seen[key] = signal
    missing = REQUIRED_SIGNAL_KEYS - set(seen)
    defects += len(missing)

    # Stage receipts are not independent booleans.  A terminal home-page
    # failure means that every fact derived from that representation has the
    # same checked/unchecked state.  Rejecting incoherent combinations here
    # keeps forged ``home=False`` + successful page facts from becoming a
    # complete, scored report in either the library or its gateway projection.
    home = seen.get("home")
    if home is not None and home.ok in {False, None}:
        expected = home.ok
        defects += sum(
            1
            for key in _PAGE_DERIVED_SIGNAL_KEYS
            if key in seen and seen[key].ok is not expected
        )

    # This row is emitted only as a negative diagnostic while parsing a full
    # page representation.  It is never a positive bonus and is nonsensical
    # beside a terminal/unavailable home stage.
    jsonld_diagnostic = seen.get("jsonld_valid")
    if jsonld_diagnostic is not None and (
        jsonld_diagnostic.ok is not False
        or home is None
        or home.ok is not True
        or any(
            key not in seen or seen[key].ok is None
            for key in _PAGE_DERIVED_SIGNAL_KEYS
        )
    ):
        defects += 1
    optional_weight = sum(
        SIGNAL_WEIGHT_CONTRACT[key]
        for key in OPTIONAL_SIGNAL_KEYS if key in seen
    )
    error_count = len(errors or [])
    unchecked_zero_weight_receipts = sum(
        1
        for key, signal in seen.items()
        if SIGNAL_WEIGHT_CONTRACT[key] == 0 and signal.ok is None
    )
    denominator = (
        sum(SIGNAL_WEIGHT_CONTRACT[key] for key in REQUIRED_SIGNAL_KEYS)
        + optional_weight
        + defects
        + error_count
        + unchecked_zero_weight_receipts
    )
    checked = sum(
        SIGNAL_WEIGHT_CONTRACT[key]
        for key, signal in seen.items()
        if signal.ok is not None
    )
    complete = defects == 0 and not missing
    return complete, checked, denominator


@dataclass
class Report:
    url: str
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def scored(self) -> list[Signal]:
        return [s for s in self.signals if s.ok is not None]

    @property
    def score(self) -> int | None:
        """Percent passed, but only when the complete check set ran.

        An unreachable document is not evidence that a site failed its page
        basics, so it is not folded into the denominator as a failure.  It is
        equally unsafe to publish ``100`` over the surviving subset.  Partial
        reports therefore have no score and expose coverage separately.
        """
        if not self.successful:
            return None
        total = sum(s.weight for s in self.signals)
        if not total:
            return 0
        got = sum(s.weight for s in self.scored if s.ok)
        return round(100 * got / total)

    @property
    def coverage_percent(self) -> int:
        """Weighted share of expected checks that actually returned a result.

        The denominator is the fixed official contract, not whichever rows a
        producer happened to return.  Errors and contract defects each add a
        missing unit, including a missing zero-weight stage receipt, so an
        incomplete or malformed report can never advertise 100% coverage.
        """
        _complete, checked, total = _signal_contract_facts(
            self.signals, self.errors)
        if not total:
            return 0
        return round(100 * checked / total)

    @property
    def unchecked(self) -> list[Signal]:
        return [s for s in self.signals if s.ok is None]

    @property
    def successful(self) -> bool:
        """Whether the exact signal contract completed without an error.

        ``score`` remains a ratio over the signals that were actually
        evaluated.  It is deliberately not a substitute for this completion
        flag: a partial report can have a high diagnostic score and still be
        an unsuccessful run.
        """
        contract_complete, _checked, _total = _signal_contract_facts(
            self.signals, self.errors)
        return contract_complete and not self.errors and not self.unchecked


class UnsafeTarget(ValueError):
    """Raised before a request can reach a non-public network target."""


_ASCII_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _ascii_lower(value: str) -> str:
    """Apply HTML/URL ASCII case folding without Unicode confusable folding."""
    return value.translate(_ASCII_LOWER)


_HTML_ASCII_WHITESPACE = "\t\n\f\r "


def _html_ascii_strip(value: str) -> str:
    """Strip only the five whitespace characters defined by HTML.

    Python's Unicode-aware ``str.strip`` and ``str.split`` would turn NBSP
    and other Unicode separators into HTML token delimiters.  Browsers do not,
    so doing that here could promote an attacker-controlled attribute token.
    """
    return value.strip(_HTML_ASCII_WHITESPACE)


def _html_ascii_split(value: str) -> list[str]:
    return [
        token for token in re.split(r"[\x09\x0a\x0c\x0d\x20]+", value)
        if token
    ]


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("request deadline exceeded")
    return remaining


def _canonical_target(url: str) -> tuple[str, str, int, str, str]:
    """Return (url, host, port, request_target, host_header).

    Only ordinary public-web HTTP(S) endpoints are accepted.  User-info and
    unusual ports are deliberately excluded because this function is also
    used by the hosted checker, where a permissive URL parser becomes SSRF.
    """
    if not isinstance(url, str) or not url.strip():
        raise UnsafeTarget("site address is required")
    raw = url.strip()
    if len(raw) > MAX_URL_CHARS:
        raise UnsafeTarget("site address is too long")
    if not re.match(r"(?i)^https?://", raw):
        raw = "https://" + raw
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTarget("only http and https sites are supported")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeTarget("credentials in a site address are not allowed")
    host = (parsed.hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        raise UnsafeTarget("site address is malformed") from exc
    # A hosted website must be a DNS name.  Rejecting literal addresses and
    # single-label names also closes the alternate-numeric-IP spellings that
    # URL libraries and operating systems do not interpret consistently.
    try:
        ipaddress.ip_address(host)
        literal_ip = True
    except ValueError:
        literal_ip = False
    if not host or "." not in host or literal_ip:
        raise UnsafeTarget("not a public site address")
    if port not in {80, 443}:
        raise UnsafeTarget("only standard web ports 80 and 443 are supported")
    path = parsed.path or "/"
    target = path + (("?" + parsed.query) if parsed.query else "")
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    try:
        is_v6 = ipaddress.ip_address(host).version == 6
    except ValueError:
        is_v6 = False
    display_host = f"[{host}]" if is_v6 else host
    host_header = display_host if port == default_port else f"{display_host}:{port}"
    canonical = urlunsplit((parsed.scheme.lower(), host_header, path,
                            parsed.query, ""))
    return canonical, host, port, target, host_header


_DNS_PROBE = (
    "import json,socket,sys;"
    "h=sys.argv[1];p=int(sys.argv[2]);"
    "i=socket.getaddrinfo(h,p,type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP);"
    "print(json.dumps(sorted({str(x[4][0]).split('%',1)[0] for x in i})))"
)


def _resolve_public(
        host: str, port: int, *, deadline: float | None = None) -> list[str]:
    """Resolve once, with a killable subprocess when a deadline is active.

    CPython cannot cancel a thread blocked inside the platform resolver.  The
    bounded path therefore isolates DNS in a child process; ``subprocess.run``
    kills and waits for that child on timeout, so a slow resolver cannot leave
    a worker or handle behind after the request has returned.
    """
    try:
        if deadline is None:
            infos = socket.getaddrinfo(
                host, port, type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP)
            addresses = sorted({
                str(info[4][0]).split("%", 1)[0] for info in infos
            })
        else:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", _DNS_PROBE, host, str(port)],
                capture_output=True,
                text=True,
                timeout=_remaining(deadline),
                check=False,
            )
            if completed.returncode != 0:
                raise OSError("resolver child failed")
            payload = json.loads(completed.stdout)
            if not isinstance(payload, list) or any(
                    not isinstance(value, str) for value in payload):
                raise OSError("resolver child returned malformed output")
            addresses = sorted(set(payload))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError,
            TimeoutError) as exc:
        raise UnsafeTarget("site address could not be resolved") from exc
    if not addresses or any(not _is_public_ip(value) for value in addresses):
        raise UnsafeTarget("private, local, reserved, or mixed network targets are blocked")
    return addresses


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to the address that passed validation, never a second DNS result."""

    def __init__(self, host: str, port: int, address: str, *, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, *, timeout: float):
        super().__init__(host, port=port, timeout=timeout,
                         context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _response_header_values(response: http.client.HTTPResponse, name: str) -> list[str]:
    try:
        headers = response.getheaders()
    except (AttributeError, TypeError):
        headers = None
    if isinstance(headers, (list, tuple)):
        return [
            str(value) for key, value in headers
            if isinstance(key, str) and key.lower() == name.lower()
        ]
    value = response.getheader(name)
    return [str(value)] if value not in {None, ""} else []


def _validated_content_type_header(response: http.client.HTTPResponse) -> str:
    values = _response_header_values(response, "Content-Type")
    if len(values) > 1:
        raise ValueError("duplicate Content-Type header")
    value = values[0].strip() if values else ""
    if "\r" in value or "\n" in value:
        raise ValueError("invalid Content-Type header")
    return value


def _validated_content_encoding_header(response: http.client.HTTPResponse) -> str:
    """Accept only the representation explicitly requested from the server.

    The checker asks for ``identity``.  Parsing a compressed or multiply
    declared representation as if it were the decoded resource would make
    every downstream signal untrustworthy, so it fails closed here.
    """
    values = _response_header_values(response, "Content-Encoding")
    if len(values) > 1:
        raise ValueError("duplicate Content-Encoding header")
    value = _ascii_lower(values[0].strip()) if values else ""
    if "\r" in value or "\n" in value or "," in value:
        raise ValueError("invalid Content-Encoding header")
    if value not in {"", "identity"}:
        raise ValueError("unsupported Content-Encoding header")
    return value


def _fetch_once(
        url: str, *, deadline: float | None = None
) -> tuple[int, bytes, str, str, str]:
    if deadline is None:
        deadline = getattr(_deadline_state, "value", None)
    if deadline is None:
        deadline = time.monotonic() + TIMEOUT
    canonical, host, port, target, host_header = _canonical_target(url)
    addresses = _resolve_public(host, port, deadline=deadline)
    conn_cls = (_PinnedHTTPSConnection if canonical.startswith("https://")
                else _PinnedHTTPConnection)
    conn = conn_cls(host, port, addresses[0], timeout=_remaining(deadline))
    expired = threading.Event()

    def expire_connection() -> None:
        expired.set()
        conn.close()

    watchdog = threading.Timer(_remaining(deadline), expire_connection)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request("GET", target, headers={
            "Host": host_header,
            "User-Agent": USER_AGENT,
            "Accept": "text/html,text/plain,application/xml,text/xml;q=0.9,*/*;q=0.1",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        if conn.sock is not None:
            conn.sock.settimeout(_remaining(deadline))
        response = conn.getresponse()
        location = response.getheader("Location") or ""
        # Error/redirect semantics belong to the status line, not to an error
        # representation.  Do not let a missing, duplicate, or malformed body
        # Content-Type erase a genuine HTTP response into synthetic status 0.
        if not 200 <= response.status < 300:
            return response.status, b"", "", "", location
        try:
            content_type = _validated_content_type_header(response)
        except ValueError:
            return response.status, b"", "", "invalid", location
        try:
            content_encoding = _validated_content_encoding_header(response)
        except ValueError:
            return response.status, b"", content_type, "invalid", location
        chunks: list[bytes] = []
        total = 0
        # HTTPResponse.read(n) may internally wait for exactly n bytes and
        # reset the socket timeout on every recv.  read1 performs at most one
        # buffered raw read, letting this loop recompute the absolute deadline
        # after every arriving fragment instead of granting a trickling peer a
        # fresh timeout indefinitely.
        reader = (response.read1 if callable(
            getattr(type(response), "read1", None)) else response.read)
        while total <= MAX_BODY_BYTES:
            if conn.sock is not None:
                conn.sock.settimeout(_remaining(deadline))
            amount = min(HTTP_READ_CHUNK, MAX_BODY_BYTES + 1 - total)
            chunk = reader(amount)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_BODY_BYTES:
                return response.status, b"", content_type, "invalid", location
        raw = b"".join(chunks)
        if expired.is_set():
            raise TimeoutError("request deadline exceeded")
        return response.status, raw, content_type, content_encoding, location
    finally:
        watchdog.cancel()
        conn.close()
        # Timer.cancel() does not join an already-started callback.  Wait for
        # it unconditionally so _fetch_once never returns with a watchdog
        # worker still alive.
        watchdog.join()


@dataclass(frozen=True, eq=False)
class _FetchDocument:
    status: int
    body: str
    content_type: str = ""
    content_encoding: str = ""

    def __iter__(self):
        yield self.status
        yield self.body

    def __eq__(self, other: object) -> bool:
        if isinstance(other, _FetchDocument):
            return (self.status, self.body, self.content_type,
                    self.content_encoding) == (
                other.status, other.body, other.content_type,
                other.content_encoding)
        if isinstance(other, tuple):
            return (self.status, self.body) == other
        return NotImplemented


def _parse_content_type(value: str) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value:
        return None
    pieces = [piece.strip() for piece in value.split(";")]
    media_type = _ascii_lower(pieces[0])
    if re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media_type) is None:
        return None
    params: dict[str, str] = {}
    for raw in pieces[1:]:
        if not raw or "=" not in raw:
            return None
        key, item = (part.strip() for part in raw.split("=", 1))
        key = _ascii_lower(key)
        if key in params or re.fullmatch(r"[a-z0-9!#$&^_.+-]+", key) is None:
            return None
        if len(item) >= 2 and item[0] == item[-1] == '"':
            item = item[1:-1]
        elif '"' in item:
            return None
        if not item or any(ord(character) < 0x20 for character in item):
            return None
        params[key] = item
    charset_label = params.get("charset", "utf-8")
    encoding = webencodings.lookup(charset_label)
    if encoding is None:
        return None
    return media_type, encoding.name


def _content_type(
        result: object, allowed: frozenset[str]) -> tuple[bool, str]:
    # Two-item tuples remain accepted only as a unit-test seam.  Every real
    # network result is _FetchDocument and therefore carries the header.
    if not isinstance(result, _FetchDocument):
        return True, "utf-8"
    if _ascii_lower(result.content_encoding.strip()) not in {"", "identity"}:
        return False, "utf-8"
    parsed = _parse_content_type(result.content_type)
    if parsed is None or parsed[0] not in allowed:
        return False, "utf-8"
    return True, parsed[1]


def _get(url: str, *, deadline: float | None = None) -> _FetchDocument:
    if deadline is None:
        deadline = time.monotonic() + TIMEOUT
    current = url
    previous_deadline = getattr(_deadline_state, "value", None)
    _deadline_state.value = deadline
    try:
        initial, initial_host, initial_port, _target, _header = _canonical_target(
            current)
        initial_origin = (urlsplit(initial).scheme, initial_host, initial_port)
        for redirect_count in range(MAX_REDIRECTS + 1):
            _remaining(deadline)
            status, raw, content_type, content_encoding, location = _fetch_once(
                current)
            if status in {301, 302, 303, 307, 308}:
                if not location or redirect_count >= MAX_REDIRECTS:
                    return _FetchDocument(
                        status, "", content_type, content_encoding)
                candidate = urljoin(current, location)
                try:
                    canonical, host, port, _target, _header = _canonical_target(
                        candidate)
                except UnsafeTarget:
                    return _FetchDocument(status, "", "")
                # The privacy contract promises that a submitted check talks
                # only to that origin.  A redirect may not silently turn one
                # submitted site into a fetch from another controller.
                if (urlsplit(canonical).scheme, host, port) != initial_origin:
                    return _FetchDocument(status, "", "")
                current = canonical
                continue
            # Preserve the server's HTTP semantics before trying to interpret
            # representation metadata or bytes.  A real 4xx/5xx is a checked
            # response, even when its error body is empty, malformed, or has no
            # Content-Type.  Only transport failure is represented by status 0.
            if not 200 <= status < 300:
                return _FetchDocument(
                    status, "", content_type, content_encoding)
            parsed_type = _parse_content_type(content_type)
            if parsed_type is None:
                return _FetchDocument(
                    status, "", content_type, content_encoding)
            encoding = webencodings.lookup(parsed_type[1])
            if encoding is None:  # guarded by _parse_content_type
                return _FetchDocument(
                    status, "", content_type, content_encoding)
            try:
                body, _used_encoding = webencodings.decode(
                    raw, encoding, errors="strict")
            except UnicodeDecodeError:
                return _FetchDocument(
                    status, "", content_type, content_encoding)
            return _FetchDocument(
                status, body, content_type, content_encoding)
        return _FetchDocument(0, "", "")
    except UnsafeTarget:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError,
            TimeoutError):
        return _FetchDocument(0, "", "")
    finally:
        if previous_deadline is None:
            try:
                del _deadline_state.value
            except AttributeError:
                pass
        else:
            _deadline_state.value = previous_deadline


def normalise(url: str) -> str:
    canonical, _host, _port, _target, _header = _canonical_target(url)
    return canonical


# ── individual checks ──────────────────────────────────────────────────────
def _robots_groups(body: str) -> list[tuple[tuple[str, ...], tuple[tuple[str, str], ...]]]:
    """Parse enough of RFC 9309 to decide whether the site root is crawlable.

    A new user-agent after rules begins a new group even when the publisher
    omitted a blank line.  This matters because an unrelated wildcard group
    must not inherit the rules of a later crawler-specific group.
    """
    groups: list[tuple[tuple[str, ...], tuple[tuple[str, str], ...]]] = []
    agents: list[str] = []
    rules: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal agents, rules
        if agents:
            groups.append((tuple(agents), tuple(rules)))
        agents, rules = [], []

    for raw_line in body.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field_, value = (part.strip() for part in line.split(":", 1))
        field_ = field_.lower()
        if field_ == "user-agent":
            if rules:
                flush()
            agents.append(value.lower())
        elif field_ in {"allow", "disallow"} and agents:
            rules.append((field_, value))
    flush()
    return groups


_PERCENT_OCTET = re.compile(r"%([0-9a-fA-F]{2})")
_URI_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _normalise_robots_octets(value: str) -> str:
    """Apply RFC 9309's required URI-octet comparison normalisation.

    Percent-encoded ASCII octets in the URI unreserved set compare as their
    literal characters.  Reserved and non-ASCII octets stay encoded; their
    hexadecimal digits are only canonicalised to upper case.  In particular,
    ``%2F`` must never become a path separator and ``%2A`` must never become a
    robots wildcard.
    """

    def replace(match: re.Match[str]) -> str:
        octet = int(match.group(1), 16)
        character = chr(octet)
        if octet < 128 and character in _URI_UNRESERVED:
            return character
        return f"%{octet:02X}"

    return _PERCENT_OCTET.sub(replace, value)


def _rule_matches_path(rule: str, path: str) -> bool:
    """Match the wildcard/end-anchor subset required by RFC 9309."""
    if not rule:
        return False
    rule = _normalise_robots_octets(rule)
    path = _normalise_robots_octets(path)
    anchored = rule.endswith("$")
    body = rule[:-1] if anchored else rule
    expression = "^" + re.escape(body).replace(r"\*", ".*")
    if anchored:
        expression += "$"
    return re.search(expression, path) is not None


def _path_blocked(groups, crawler: str, path: str) -> bool:
    crawler = crawler.lower()
    specific = [rules for agents, rules in groups if crawler in agents]
    applicable = specific or [rules for agents, rules in groups if "*" in agents]
    matched: list[tuple[int, bool]] = []
    for rules in applicable:
        for directive, value in rules:
            if not _rule_matches_path(value, path):
                continue
            normalised = _normalise_robots_octets(value)
            specificity = len(
                normalised.rstrip("$").replace("*", "").encode("utf-8"))
            matched.append((specificity, directive == "allow"))
    if not matched:
        return False
    longest = max(length for length, _allowed in matched)
    # RFC 9309 gives Allow precedence when equally specific rules conflict.
    return not any(allowed for length, allowed in matched if length == longest)


def _root_blocked(groups, crawler: str) -> bool:
    """Compatibility helper retained for callers that explicitly mean `/`."""
    return _path_blocked(groups, crawler, "/")


_ROBOTS_CHILD_MAX_BYTES = MAX_BODY_BYTES + (MAX_URL_CHARS * 4) + 4_096
_ROBOTS_CHILD_MAX_OUTPUT = 64 * 1024


def _robots_evaluation_in_process(body: str, path: str) -> dict[str, list[str]]:
    """Return the three blocked-crawler classes inside an isolated process."""
    groups = _robots_groups(body)
    return {
        "answer": sorted(c for c in SEARCH_CRAWLERS
                         if _path_blocked(groups, c, path)),
        "user_fetch": sorted(c for c in USER_FETCHERS
                             if _path_blocked(groups, c, path)),
        "scrape": sorted(c for c in SCRAPE_CRAWLERS
                         if _path_blocked(groups, c, path)),
    }


def _evaluate_robots_bounded(
        body: str, path: str, *, deadline: float) -> dict[str, list[str]]:
    """Parse and match robots rules under the request's absolute deadline.

    Wildcard matching is CPU work and cannot be interrupted safely in a Python
    thread.  Run the whole parse/match in a disposable process, then kill and
    reap it before returning on timeout.  This makes a pathological robots file
    consume only the remaining request budget and leaves no zombie child.
    """
    encoded = json.dumps(
        {"body": body, "path": path},
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > _ROBOTS_CHILD_MAX_BYTES:
        raise ValueError("robots input exceeds the evaluation limit")
    process = subprocess.Popen(
        [sys.executable, "-I", str(Path(__file__).resolve()),
         "--robots-eval-child"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        try:
            stdout, _stderr = process.communicate(
                input=encoded, timeout=_remaining(deadline))
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.communicate()
            raise TimeoutError("robots evaluation deadline exceeded") from exc
        except TimeoutError:
            process.kill()
            process.communicate()
            raise
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()
    _remaining(deadline)
    if process.returncode != 0 or len(stdout) > _ROBOTS_CHILD_MAX_OUTPUT:
        raise ValueError("robots evaluator rejected the policy")
    try:
        payload = json.loads(
            stdout.decode("utf-8", "strict"),
            object_pairs_hook=_json_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("robots evaluator returned malformed facts") from exc
    expected = {"answer", "user_fetch", "scrape"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ValueError("robots evaluator returned an invalid fact object")
    allowed = {
        "answer": frozenset(SEARCH_CRAWLERS),
        "user_fetch": frozenset(USER_FETCHERS),
        "scrape": frozenset(SCRAPE_CRAWLERS),
    }
    for key in expected:
        values = payload[key]
        if (not isinstance(values, list)
                or any(not isinstance(value, str) for value in values)
                or len(values) != len(set(values))
                or not set(values) <= allowed[key]):
            raise ValueError("robots evaluator returned invalid crawler facts")
    _remaining(deadline)
    return payload


def check_robots(base: str, *, deadline: float | None = None) -> list[Signal]:
    result = _get(urljoin(base, "/robots.txt"), deadline=deadline)
    status, body = result
    parsed = urlsplit(base)
    submitted_path = parsed.path or "/"
    if parsed.query:
        submitted_path += "?" + parsed.query
    if status == 0:
        return [Signal("robots", None,
                       "robots.txt could not be fetched; no site-policy result was inferred",
                       2)]
    if 400 <= status < 500:
        # RFC 9309 defines an unavailable robots file (4xx) as no restrictions.
        return [Signal("robots", True,
                       f"robots.txt is unavailable (HTTP {status}); RFC crawler policy treats it as no declared restrictions",
                       2)]
    if 500 <= status < 600:
        return [Signal("robots", False,
                       f"robots.txt is unreachable (HTTP {status}); crawlers may temporarily treat the site as disallowed",
                       2)]
    if status != 200:
        return [Signal("robots", False,
                       f"robots.txt could not be evaluated as a full HTTP 200 "
                       f"representation (HTTP {status})", 2)]
    type_ok, _charset = _content_type(result, frozenset({"text/plain"}))
    if not type_ok:
        return [Signal("robots", False,
                       "robots.txt was not served as text/plain", 2)]

    if deadline is None:
        deadline = time.monotonic() + TIMEOUT
    blocked = _evaluate_robots_bounded(
        body, submitted_path, deadline=deadline)
    answer = blocked["answer"]
    user_fetch = blocked["user_fetch"]
    scrape = blocked["scrape"]
    if answer:
        return [Signal("robots", False,
                       f"robots.txt blocks search crawlers on {submitted_path}: "
                       + ", ".join(answer), 2, evidence="/robots.txt")]
    detail = f"declared robots policy allows search crawlers on {submitted_path}"
    if user_fetch:
        detail += (" (user-triggered fetchers blocked, informational only: "
                   + ", ".join(user_fetch) + ")")
    if scrape:
        detail += (" (training/model-use crawlers blocked by policy: "
                   + ", ".join(scrape) + ")")
    return [Signal("robots", True, detail, 2)]


def check_llms_txt(base: str, *, deadline: float | None = None) -> list[Signal]:
    result = _get(urljoin(base, "/llms.txt"), deadline=deadline)
    status, body = result
    if status == 0:
        return [Signal("llms_txt", None, "/llms.txt could not be fetched", 0)]
    type_ok, _charset = _content_type(result, frozenset({
        "text/plain", "text/markdown", "text/x-markdown",
    }))
    ok = status == 200 and type_ok and len(body.strip()) > 200
    return [Signal(
        "llms_txt", ok,
        "an experimental /llms.txt summary is published (not a web standard)" if ok
        else "no /llms.txt (informational only: it is not a web standard and "
             "Google Search does not use it)",
        0, evidence="/llms.txt")]


def check_sitemap(base: str, *, deadline: float | None = None) -> list[Signal]:
    result = _get(urljoin(base, "/sitemap.xml"), deadline=deadline)
    status, body = result
    if status == 0:
        return [Signal("sitemap", None, "sitemap could not be fetched")]
    ok = False
    kind = ""
    count = 0
    lower_body = body.lower()
    type_ok, _charset = _content_type(result, frozenset({
        "application/xml", "text/xml",
    }))
    if (status == 200 and type_ok and body.strip()
            and "<!doctype" not in lower_body
            and "<!entity" not in lower_body):
        try:
            root = ET.fromstring(body)
            namespace, kind = _xml_name(root.tag)
            expected_record = {
                "urlset": "url",
                "sitemapindex": "sitemap",
            }.get(kind)
            expected_authority = _public_web_authority(base)
            if (expected_record is not None
                    and expected_authority is not None
                    and namespace == _SITEMAP_NAMESPACE):
                records = list(root)
                valid_records = [
                    _valid_sitemap_record(
                        record, namespace, expected_record,
                        expected_authority=expected_authority,
                    )
                    for record in records
                ]
                ok = bool(records) and all(valid_records)
                count = len(records) if ok else 0
        except ET.ParseError:
            pass
    return [Signal("sitemap", ok,
                   f"valid {kind} sitemap with {count} location(s)" if ok
                   else "no valid XML sitemap with at least one location",
                   1, evidence="/sitemap.xml")]


_HTML_NAMESPACE = "http://www.w3.org/1999/xhtml"
_INERT_ANCESTORS = frozenset({
    "iframe", "noembed", "noframes", "noscript", "plaintext", "script",
    "style", "template", "textarea", "xmp",
})


def _dom_name(tag: object) -> tuple[str, str]:
    """Return an ElementTree namespace/local-name pair."""
    if not isinstance(tag, str):
        return "", ""
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return "", tag


_CSS_WHITESPACE = " \t\n\r\f"
_CSS_HEX = frozenset("0123456789abcdefABCDEF")
_CSS_TOKEN_NUMBER = re.compile(
    r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?"
)
_CSS_RELEVANT_PROPERTIES = frozenset({
    "display", "visibility", "opacity", "content-visibility",
})
_CSS_OPEN_KINDS = frozenset({"function", "lparen", "lbracket", "lbrace"})
_CSS_CLOSE_KINDS = frozenset({"rparen", "rbracket", "rbrace"})
_CSS_MAX_RESOLVED_TOKENS = MAX_HTML_BYTES


@dataclass(frozen=True)
class _CSSToken:
    """One CSS Syntax token; escapes are decoded without losing token kind."""

    kind: str
    value: str = ""
    number: float | None = None


@dataclass(frozen=True)
class _CSSDeclaration:
    name: str
    value: tuple[_CSSToken, ...]
    important: bool
    order: int
    specificity: tuple[int, int, int, int] = (0, 0, 0, 0)


class _CSSLimitExceeded(ValueError):
    """A valid-looking CSS expansion exceeded the document-sized budget."""


def _css_name_start(character: str) -> bool:
    return bool(character) and (
        character == "_"
        or "A" <= character <= "Z"
        or "a" <= character <= "z"
        or ord(character) >= 0x80
    )


def _css_name(character: str) -> bool:
    return _css_name_start(character) or character == "-" or character.isascii() \
        and character.isdigit()


def _css_valid_escape(source: str, position: int) -> bool:
    return (
        position < len(source)
        and source[position] == "\\"
        and position + 1 < len(source)
        and source[position + 1] not in "\n\r\f"
    )


def _css_consume_escape(source: str, position: int) -> tuple[str, int]:
    """Consume a verified CSS escape beginning at ``position``."""
    cursor = position + 1
    if cursor >= len(source):
        return "\ufffd", cursor
    if source[cursor] in _CSS_HEX:
        start = cursor
        cursor += 1
        while (
            cursor < len(source)
            and cursor - start < 6
            and source[cursor] in _CSS_HEX
        ):
            cursor += 1
        scalar = int(source[start:cursor], 16)
        if scalar == 0 or scalar > 0x10FFFF or 0xD800 <= scalar <= 0xDFFF:
            character = "\ufffd"
        else:
            character = chr(scalar)
        if cursor < len(source) and source[cursor] in _CSS_WHITESPACE:
            if (
                source[cursor] == "\r"
                and cursor + 1 < len(source)
                and source[cursor + 1] == "\n"
            ):
                cursor += 2
            else:
                cursor += 1
        return character, cursor
    character = source[cursor]
    return ("\ufffd" if character == "\x00" else character), cursor + 1


def _css_would_start_ident(source: str, position: int) -> bool:
    first = source[position] if position < len(source) else ""
    second = source[position + 1] if position + 1 < len(source) else ""
    if first == "-":
        return (
            _css_name_start(second)
            or second == "-"
            or _css_valid_escape(source, position + 1)
        )
    return _css_name_start(first) or _css_valid_escape(source, position)


def _css_consume_ident(source: str, position: int) -> tuple[str, int]:
    result: list[str] = []
    cursor = position
    while cursor < len(source):
        character = source[cursor]
        if _css_name(character):
            result.append("\ufffd" if character == "\x00" else character)
            cursor += 1
        elif _css_valid_escape(source, cursor):
            decoded, cursor = _css_consume_escape(source, cursor)
            result.append(decoded)
        else:
            break
    return "".join(result), cursor


def _css_tokens(value: str) -> tuple[_CSSToken, ...] | None:
    """Tokenize the CSS Syntax subset needed by the rendering projection.

    Comments are consumed only at token boundaries, strings own their content,
    and a function token exists only when ``(`` immediately follows its ident.
    Those three properties are the security boundary lost by textual regexes.
    """
    if not isinstance(value, str) or len(value) > MAX_HTML_BYTES:
        return None
    tokens: list[_CSSToken] = []
    cursor = 0
    punctuation = {
        ":": "colon", ";": "semicolon", ",": "comma",
        "(": "lparen", ")": "rparen", "[": "lbracket",
        "]": "rbracket", "{": "lbrace", "}": "rbrace",
    }
    while cursor < len(value):
        if len(tokens) > MAX_HTML_BYTES:
            return None
        character = value[cursor]
        if character in _CSS_WHITESPACE:
            cursor += 1
            while cursor < len(value) and value[cursor] in _CSS_WHITESPACE:
                cursor += 1
            tokens.append(_CSSToken("whitespace", " "))
            continue
        if value.startswith("/*", cursor):
            end = value.find("*/", cursor + 2)
            cursor = len(value) if end < 0 else end + 2
            continue
        if character in {"'", '"'}:
            quote = character
            cursor += 1
            content: list[str] = []
            bad = False
            while cursor < len(value):
                character = value[cursor]
                if character == quote:
                    cursor += 1
                    break
                if character in "\n\r\f":
                    bad = True
                    break
                if character == "\\":
                    if cursor + 1 >= len(value):
                        cursor += 1
                        continue
                    if value[cursor + 1] in "\n\r\f":
                        cursor += 2
                        if (
                            value[cursor - 1] == "\r"
                            and cursor < len(value)
                            and value[cursor] == "\n"
                        ):
                            cursor += 1
                        continue
                    decoded, cursor = _css_consume_escape(value, cursor)
                    content.append(decoded)
                    continue
                content.append("\ufffd" if character == "\x00" else character)
                cursor += 1
            tokens.append(_CSSToken("bad-string" if bad else "string",
                                    "".join(content)))
            continue
        number_match = _CSS_TOKEN_NUMBER.match(value, cursor)
        if number_match is not None:
            raw = number_match.group(0)
            cursor = number_match.end()
            try:
                number = float(raw)
            except (ValueError, OverflowError):
                number = math.nan
            if cursor < len(value) and value[cursor] == "%":
                tokens.append(_CSSToken("percentage", raw, number / 100.0))
                cursor += 1
            elif _css_would_start_ident(value, cursor):
                unit, cursor = _css_consume_ident(value, cursor)
                tokens.append(_CSSToken("dimension", unit, number))
            else:
                tokens.append(_CSSToken("number", raw, number))
            continue
        if _css_would_start_ident(value, cursor):
            name, cursor = _css_consume_ident(value, cursor)
            if cursor < len(value) and value[cursor] == "(":
                tokens.append(_CSSToken("function", name))
                cursor += 1
            else:
                tokens.append(_CSSToken("ident", name))
            continue
        kind = punctuation.get(character)
        if kind is not None:
            tokens.append(_CSSToken(kind, character))
            cursor += 1
            continue
        tokens.append(_CSSToken("delim", "\ufffd" if character == "\x00"
                                else character))
        cursor += 1
    return tuple(tokens)


def _css_trim(tokens: tuple[_CSSToken, ...]) -> tuple[_CSSToken, ...]:
    start = 0
    end = len(tokens)
    while start < end and tokens[start].kind == "whitespace":
        start += 1
    while end > start and tokens[end - 1].kind == "whitespace":
        end -= 1
    return tokens[start:end]


def _css_balanced(tokens: tuple[_CSSToken, ...]) -> bool:
    stack: list[str] = []
    pairs = {"rparen": {"function", "lparen"},
             "rbracket": {"lbracket"}, "rbrace": {"lbrace"}}
    for token in tokens:
        if token.kind in _CSS_OPEN_KINDS:
            stack.append(token.kind)
        elif token.kind in _CSS_CLOSE_KINDS:
            if not stack or stack[-1] not in pairs[token.kind]:
                return False
            stack.pop()
    return not stack


def _css_split_top_level(
        tokens: tuple[_CSSToken, ...], kind: str
) -> list[tuple[_CSSToken, ...]] | None:
    parts: list[tuple[_CSSToken, ...]] = []
    start = 0
    stack: list[str] = []
    pairs = {"rparen": {"function", "lparen"},
             "rbracket": {"lbracket"}, "rbrace": {"lbrace"}}
    for index, token in enumerate(tokens):
        if token.kind in _CSS_OPEN_KINDS:
            stack.append(token.kind)
        elif token.kind in _CSS_CLOSE_KINDS:
            if not stack or stack[-1] not in pairs[token.kind]:
                return None
            stack.pop()
        elif token.kind == kind and not stack:
            parts.append(tokens[start:index])
            start = index + 1
    if stack:
        return None
    parts.append(tokens[start:])
    return parts


def _css_parse_declarations(
        tokens: tuple[_CSSToken, ...], *, order_start: int = 0,
        specificity: tuple[int, int, int, int] = (0, 0, 0, 0),
) -> list[_CSSDeclaration]:
    rows = _css_split_top_level(tokens, "semicolon")
    if rows is None:
        return []
    declarations: list[_CSSDeclaration] = []
    for offset, row in enumerate(rows):
        row = _css_trim(row)
        colon = next((index for index, token in enumerate(row)
                      if token.kind == "colon"), None)
        if colon is None:
            continue
        name_tokens = tuple(
            token for token in row[:colon] if token.kind != "whitespace")
        if len(name_tokens) != 1 or name_tokens[0].kind != "ident":
            continue
        name = name_tokens[0].value
        normal_name = name if name.startswith("--") else _ascii_lower(name)
        if normal_name.startswith("--"):
            if not _css_custom_property_name_is_valid(normal_name):
                continue
        elif normal_name not in _CSS_RELEVANT_PROPERTIES:
            continue
        candidate = _css_trim(row[colon + 1:])
        if not _css_balanced(candidate):
            continue
        meaningful = [i for i, token in enumerate(candidate)
                      if token.kind != "whitespace"]
        important = False
        if len(meaningful) >= 2:
            bang_index, word_index = meaningful[-2:]
            bang = candidate[bang_index]
            word = candidate[word_index]
            if (
                bang.kind == "delim" and bang.value == "!"
                and word.kind == "ident"
                and _ascii_lower(word.value) == "important"
            ):
                important = True
                candidate = _css_trim(candidate[:bang_index])
        declarations.append(_CSSDeclaration(
            normal_name, candidate, important, order_start + offset,
            specificity,
        ))
    return declarations


def _css_custom_property_name_is_valid(value: str) -> bool:
    """A decoded name is safe after the tokenizer proved it was one ident."""
    return isinstance(value, str) and value.startswith("--") and len(value) > 2


def _css_cascade(value: str) -> dict[str, list[_CSSDeclaration]]:
    tokens = _css_tokens(value)
    if tokens is None:
        return {}
    candidates: dict[str, list[_CSSDeclaration]] = {}
    for declaration in _css_parse_declarations(tokens):
        candidates.setdefault(declaration.name, []).append(declaration)
    return {
        name: sorted(rows, key=lambda row: (
            row.important, row.specificity, row.order), reverse=True)
        for name, rows in candidates.items()
    }


def _css_function_end(
        tokens: tuple[_CSSToken, ...], start: int
) -> int | None:
    if start >= len(tokens) or tokens[start].kind != "function":
        return None
    depth = 1
    for index in range(start + 1, len(tokens)):
        token = tokens[index]
        if token.kind in {"function", "lparen"}:
            depth += 1
        elif token.kind == "rparen":
            depth -= 1
            if depth == 0:
                return index
    return None


def _css_var_arguments(
        tokens: tuple[_CSSToken, ...]
) -> tuple[str, tuple[_CSSToken, ...] | None] | None:
    rows = _css_split_top_level(tokens, "comma")
    if rows is None or len(rows) > 2:
        return None
    name_tokens = tuple(
        token for token in _css_trim(rows[0]) if token.kind != "whitespace")
    if len(name_tokens) != 1 or name_tokens[0].kind != "ident":
        return None
    name = name_tokens[0].value
    if not _css_custom_property_name_is_valid(name):
        return None
    fallback = rows[1] if len(rows) == 2 else None
    return name, fallback


def _resolve_css_vars(
        value: tuple[_CSSToken, ...],
        custom: dict[str, tuple[_CSSToken, ...]], *,
        stack: tuple[str, ...] = (), budget: list[int] | None = None,
) -> tuple[_CSSToken, ...] | None:
    """Resolve every genuine ``var()`` token under one document-sized cap."""
    if budget is None:
        budget = [_CSS_MAX_RESOLVED_TOKENS]
    output: list[_CSSToken] = []
    cursor = 0
    try:
        while cursor < len(value):
            token = value[cursor]
            if token.kind == "function":
                end = _css_function_end(value, cursor)
                if end is None:
                    return None
                inner = value[cursor + 1:end]
                if _ascii_lower(token.value) == "var":
                    parsed = _css_var_arguments(inner)
                    if parsed is None:
                        return None
                    name, fallback = parsed
                    resolved = None
                    if name not in stack and name in custom:
                        resolved = _resolve_css_vars(
                            custom[name], custom, stack=stack + (name,),
                            budget=budget)
                    if resolved is None and fallback is not None:
                        resolved = _resolve_css_vars(
                            fallback, custom, stack=stack + (name,),
                            budget=budget)
                    if resolved is None:
                        return None
                    output.extend(resolved)
                else:
                    resolved_inner = _resolve_css_vars(
                        inner, custom, stack=stack, budget=budget)
                    if resolved_inner is None:
                        return None
                    output.append(token)
                    output.extend(resolved_inner)
                    output.append(value[end])
                cursor = end + 1
                continue
            output.append(token)
            cursor += 1
            budget[0] -= 1
            if budget[0] < 0:
                raise _CSSLimitExceeded("CSS variable expansion exceeds cap")
        return tuple(output)
    except RecursionError as exc:
        raise _CSSLimitExceeded("CSS variable expansion depth exceeds runtime") from exc


_CSS_WIDE_VALUES = frozenset({
    "inherit", "initial", "revert", "revert-layer", "unset",
})
_DISPLAY_SINGLE_VALUES = frozenset({
    "block", "contents", "flex", "flow", "flow-root", "grid", "inline",
    "inline-block", "inline-flex", "inline-grid", "inline-table",
    "list-item", "math", "none", "ruby", "run-in", "table",
    "table-caption", "table-cell", "table-column", "table-column-group",
    "table-footer-group", "table-header-group", "table-row",
    "table-row-group",
})
_DISPLAY_OUTSIDE_VALUES = frozenset({"block", "inline", "run-in"})
_DISPLAY_INSIDE_VALUES = frozenset({
    "flex", "flow", "flow-root", "grid", "math", "ruby", "table",
})
_CSS_MATH_FUNCTIONS = frozenset({
    "abs", "calc", "clamp", "exp", "hypot", "log", "max", "min",
    "mod", "pow", "rem", "round", "sign", "sqrt",
})
_CSS_ROUND_STRATEGIES = frozenset({"nearest", "up", "down", "to-zero"})
_CSS_MATH_CONSTANTS = {
    "e": math.e,
    "pi": math.pi,
    "infinity": math.inf,
    "-infinity": -math.inf,
    "nan": math.nan,
}


def _display_value_is_valid(value: str) -> bool:
    if value in _CSS_WIDE_VALUES or value in _DISPLAY_SINGLE_VALUES:
        return True
    words = value.split()
    if not 2 <= len(words) <= 3 or len(words) != len(set(words)):
        return False
    if "list-item" in words:
        companions = [word for word in words if word != "list-item"]
        return (
            sum(word in _DISPLAY_OUTSIDE_VALUES for word in companions) <= 1
            and sum(word in {"flow", "flow-root"} for word in companions) <= 1
            and all(
                word in _DISPLAY_OUTSIDE_VALUES | {"flow", "flow-root"}
                for word in companions
            )
        )
    return (
        len(words) == 2
        and sum(word in _DISPLAY_OUTSIDE_VALUES for word in words) == 1
        and sum(word in _DISPLAY_INSIDE_VALUES for word in words) == 1
    )


@dataclass(frozen=True)
class _CSSNumeric:
    value: float
    percent_power: int = 0


class _CSSMathError(ValueError):
    pass


class _CSSUnknownMath(_CSSMathError):
    pass


def _css_same_type(values: list[_CSSNumeric]) -> int:
    if not values or any(item.percent_power != values[0].percent_power
                         for item in values[1:]):
        raise _CSSMathError("inconsistent CSS numeric types")
    return values[0].percent_power


def _css_divide(left: float, right: float) -> float:
    if right != 0:
        return left / right
    if left == 0 or math.isnan(left):
        return math.nan
    sign = math.copysign(1.0, left) * math.copysign(1.0, right)
    return math.copysign(math.inf, sign)


class _CSSMathParser:
    """Typed recursive-descent parser over CSS Syntax tokens."""

    def __init__(self, tokens: tuple[_CSSToken, ...]):
        self.tokens = tokens
        self.position = 0

    def _skip_whitespace(self) -> int:
        start = self.position
        while (self.position < len(self.tokens)
               and self.tokens[self.position].kind == "whitespace"):
            self.position += 1
        return self.position - start

    def parse(self) -> _CSSNumeric:
        self._skip_whitespace()
        result = self._sum()
        self._skip_whitespace()
        if self.position != len(self.tokens):
            raise _CSSMathError("trailing CSS numeric token")
        return result

    def _sum(self) -> _CSSNumeric:
        left = self._product()
        while True:
            checkpoint = self.position
            before = self._skip_whitespace()
            if self.position >= len(self.tokens):
                self.position = checkpoint
                break
            token = self.tokens[self.position]
            if token.kind != "delim" or token.value not in {"+", "-"}:
                self.position = checkpoint
                break
            if before == 0:
                raise _CSSMathError("binary +/- requires preceding whitespace")
            self.position += 1
            if self._skip_whitespace() == 0:
                raise _CSSMathError("binary +/- requires following whitespace")
            right = self._product()
            if left.percent_power != right.percent_power:
                raise _CSSMathError("addition requires consistent types")
            left = _CSSNumeric(
                left.value + right.value if token.value == "+"
                else left.value - right.value,
                left.percent_power,
            )
        return left

    def _product(self) -> _CSSNumeric:
        left = self._unary()
        while True:
            checkpoint = self.position
            self._skip_whitespace()
            if self.position >= len(self.tokens):
                self.position = checkpoint
                break
            token = self.tokens[self.position]
            if token.kind != "delim" or token.value not in {"*", "/"}:
                self.position = checkpoint
                break
            self.position += 1
            self._skip_whitespace()
            right = self._unary()
            if token.value == "*":
                left = _CSSNumeric(
                    left.value * right.value,
                    left.percent_power + right.percent_power,
                )
            else:
                left = _CSSNumeric(
                    _css_divide(left.value, right.value),
                    left.percent_power - right.percent_power,
                )
        return left

    def _unary(self) -> _CSSNumeric:
        self._skip_whitespace()
        if self.position < len(self.tokens):
            token = self.tokens[self.position]
            if token.kind == "delim" and token.value in {"+", "-"}:
                self.position += 1
                operand = self._unary()
                return _CSSNumeric(
                    operand.value if token.value == "+" else -operand.value,
                    operand.percent_power,
                )
        return self._primary()

    def _primary(self) -> _CSSNumeric:
        self._skip_whitespace()
        if self.position >= len(self.tokens):
            raise _CSSMathError("missing CSS numeric value")
        token = self.tokens[self.position]
        if token.kind in {"number", "percentage"}:
            self.position += 1
            if token.number is None:
                raise _CSSMathError("missing numeric token value")
            return _CSSNumeric(
                token.number, 1 if token.kind == "percentage" else 0)
        if token.kind == "ident":
            name = _ascii_lower(token.value)
            if name not in _CSS_MATH_CONSTANTS:
                raise _CSSMathError("unknown CSS numeric keyword")
            self.position += 1
            return _CSSNumeric(_CSS_MATH_CONSTANTS[name], 0)
        if token.kind == "lparen":
            end = self._matching_paren(self.position)
            inner = _CSSMathParser(self.tokens[self.position + 1:end]).parse()
            self.position = end + 1
            return inner
        if token.kind != "function":
            raise _CSSMathError("invalid CSS numeric token")
        end = self._matching_paren(self.position)
        name = _ascii_lower(token.value)
        inner = self.tokens[self.position + 1:end]
        self.position = end + 1
        if name not in _CSS_MATH_FUNCTIONS:
            raise _CSSUnknownMath(name)
        return _css_math_function(name, inner)

    def _matching_paren(self, start: int) -> int:
        depth = 1
        for index in range(start + 1, len(self.tokens)):
            token = self.tokens[index]
            if token.kind in {"function", "lparen"}:
                depth += 1
            elif token.kind == "rparen":
                depth -= 1
                if depth == 0:
                    return index
        raise _CSSMathError("unclosed CSS function")


def _css_math_arguments(
        tokens: tuple[_CSSToken, ...]
) -> list[tuple[_CSSToken, ...]]:
    rows = _css_split_top_level(tokens, "comma")
    if rows is None or any(not _css_trim(row) for row in rows):
        raise _CSSMathError("invalid CSS function arguments")
    return rows


def _css_math_function(
        name: str, tokens: tuple[_CSSToken, ...]
) -> _CSSNumeric:
    if name == "calc":
        return _CSSMathParser(tokens).parse()
    rows = _css_math_arguments(tokens)
    strategy = "nearest"
    if name == "round":
        first = tuple(token for token in _css_trim(rows[0])
                      if token.kind != "whitespace")
        if (len(first) == 1 and first[0].kind == "ident"
                and _ascii_lower(first[0].value) in _CSS_ROUND_STRATEGIES):
            strategy = _ascii_lower(first[0].value)
            rows = rows[1:]
    arguments = [_CSSMathParser(row).parse() for row in rows]
    if name in {"min", "max"} and arguments:
        power = _css_same_type(arguments)
        if any(math.isnan(item.value) for item in arguments):
            result = math.nan
        else:
            values = [item.value for item in arguments]
            result = min(values) if name == "min" else max(values)
        return _CSSNumeric(result, power)
    if name == "clamp" and len(arguments) == 3:
        power = _css_same_type(arguments)
        minimum, preferred, maximum = (item.value for item in arguments)
        result = (math.nan if any(math.isnan(item.value) for item in arguments)
                  else max(minimum, min(preferred, maximum)))
        return _CSSNumeric(result, power)
    if name == "round" and len(arguments) in {1, 2}:
        power = _css_same_type(arguments)
        number = arguments[0].value
        interval = arguments[1].value if len(arguments) == 2 else 1.0
        if (strategy not in _CSS_ROUND_STRATEGIES
                or not math.isfinite(number)
                or not math.isfinite(interval) or interval <= 0):
            result = math.nan
        else:
            quotient = number / interval
            if strategy == "nearest":
                rounded = math.floor(quotient + 0.5)
            elif strategy == "up":
                rounded = math.ceil(quotient)
            elif strategy == "down":
                rounded = math.floor(quotient)
            else:
                rounded = math.trunc(quotient)
            result = rounded * interval
        return _CSSNumeric(result, power)
    if name in {"mod", "rem"} and len(arguments) == 2:
        power = _css_same_type(arguments)
        dividend, divisor = (item.value for item in arguments)
        if (divisor == 0 or not math.isfinite(dividend)
                or not math.isfinite(divisor)):
            result = math.nan
        else:
            result = dividend % divisor if name == "mod" \
                else math.fmod(dividend, divisor)
        return _CSSNumeric(result, power)
    if name == "abs" and len(arguments) == 1:
        return _CSSNumeric(abs(arguments[0].value),
                           arguments[0].percent_power)
    if name == "sign" and len(arguments) == 1:
        number = arguments[0].value
        result = (math.nan if math.isnan(number) else
                  math.copysign(0.0, number) if number == 0 else
                  math.copysign(1.0, number))
        return _CSSNumeric(result, 0)
    if name == "hypot" and arguments:
        power = _css_same_type(arguments)
        return _CSSNumeric(math.hypot(*(item.value for item in arguments)), power)
    if name == "pow" and len(arguments) == 2 \
            and _css_same_type(arguments) == 0:
        try:
            result = math.pow(arguments[0].value, arguments[1].value)
        except ValueError:
            result = math.nan
        except OverflowError:
            result = math.inf
        return _CSSNumeric(result, 0)
    if name == "sqrt" and len(arguments) == 1 \
            and arguments[0].percent_power == 0:
        return _CSSNumeric(
            math.sqrt(arguments[0].value)
            if arguments[0].value >= 0 else math.nan, 0)
    if name == "exp" and len(arguments) == 1 \
            and arguments[0].percent_power == 0:
        try:
            result = math.exp(arguments[0].value)
        except OverflowError:
            result = math.inf
        return _CSSNumeric(result, 0)
    if name == "log" and len(arguments) in {1, 2} \
            and all(item.percent_power == 0 for item in arguments):
        number = arguments[0].value
        base = arguments[1].value if len(arguments) == 2 else math.e
        if number <= 0 or base <= 0 or base == 1:
            result = math.nan
        else:
            try:
                result = math.log(number, base)
            except (ValueError, ZeroDivisionError):
                result = math.nan
        return _CSSNumeric(result, 0)
    raise _CSSMathError("invalid CSS math function signature")


def _css_numeric_expression(
        value: tuple[_CSSToken, ...]
) -> _CSSNumeric | None:
    try:
        return _CSSMathParser(value).parse()
    except _CSSUnknownMath:
        raise
    except (_CSSMathError, OverflowError, ValueError):
        return None


def _css_single_ident(tokens: tuple[_CSSToken, ...]) -> str | None:
    meaningful = tuple(token for token in _css_trim(tokens)
                       if token.kind != "whitespace")
    if len(meaningful) == 1 and meaningful[0].kind == "ident":
        return _ascii_lower(meaningful[0].value)
    return None


def _css_keyword_sequence(tokens: tuple[_CSSToken, ...]) -> str | None:
    """Return an ASCII-folded sequence of genuine CSS identifier tokens.

    CSS whitespace is represented by its own token.  An escaped space or an
    NBSP remains inside an identifier token and therefore cannot impersonate
    the grammar separator used by a multi-keyword property such as display.
    """
    tokens = _css_trim(tokens)
    words: list[str] = []
    need_word = True
    for token in tokens:
        if token.kind == "whitespace":
            if words:
                need_word = True
            continue
        if (
            token.kind != "ident"
            or any(character.isspace() for character in token.value)
            or (words and not need_word)
        ):
            return None
        words.append(_ascii_lower(token.value))
        need_word = False
    return " ".join(words) if words else None


def _opacity_computed_value(
        value: tuple[_CSSToken, ...]
) -> tuple[bool, float | None, bool]:
    """Return ``(valid, alpha, forced_hidden)`` for an opacity declaration."""
    value = _css_trim(value)
    keyword = _css_single_ident(value)
    if keyword in _CSS_WIDE_VALUES:
        return True, None, False
    meaningful = tuple(token for token in value if token.kind != "whitespace")
    if len(meaningful) == 1 and meaningful[0].kind in {"number", "percentage"}:
        number = meaningful[0].number
        if number is None:
            return False, None, False
        return True, number if math.isfinite(number) else 0.0, False
    if meaningful and meaningful[0].kind == "function" \
            and _ascii_lower(meaningful[0].value) not in _CSS_MATH_FUNCTIONS:
        return True, 0.0, True
    try:
        numeric = _css_numeric_expression(value)
    except _CSSUnknownMath:
        return True, 0.0, True
    if numeric is None or numeric.percent_power not in {0, 1}:
        return False, None, False
    return True, numeric.value if math.isfinite(numeric.value) else 0.0, False


@dataclass(frozen=True)
class _CSSCompoundSelector:
    tag: str | None
    ids: tuple[str, ...]
    classes: tuple[str, ...]
    root: bool = False


@dataclass(frozen=True)
class _CSSSelector:
    compounds: tuple[_CSSCompoundSelector, ...]
    combinators: tuple[str, ...]
    specificity: tuple[int, int, int, int]


@dataclass(frozen=True)
class _CSSStyleRule:
    selector: _CSSSelector
    declarations: tuple[_CSSDeclaration, ...]


def _css_parse_compound_selector(
        tokens: tuple[_CSSToken, ...]
) -> _CSSCompoundSelector | None:
    if not tokens:
        return None
    cursor = 0
    tag: str | None = None
    ids: list[str] = []
    classes: list[str] = []
    root = False
    if tokens[cursor].kind == "ident":
        tag = _ascii_lower(tokens[cursor].value)
        cursor += 1
    elif tokens[cursor].kind == "delim" and tokens[cursor].value == "*":
        cursor += 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if token.kind == "delim" and token.value in {".", "#"}:
            if cursor + 1 >= len(tokens) or tokens[cursor + 1].kind != "ident":
                return None
            if token.value == ".":
                classes.append(tokens[cursor + 1].value)
            else:
                ids.append(tokens[cursor + 1].value)
            cursor += 2
            continue
        if token.kind == "colon":
            if (
                cursor + 1 >= len(tokens)
                or tokens[cursor + 1].kind != "ident"
                or _ascii_lower(tokens[cursor + 1].value) != "root"
                or root
            ):
                return None
            root = True
            cursor += 2
            continue
        return None
    if tag is None and not ids and not classes and not root:
        return None
    return _CSSCompoundSelector(tag, tuple(ids), tuple(classes), root)


def _css_parse_selector(
        tokens: tuple[_CSSToken, ...]
) -> _CSSSelector | None:
    tokens = _css_trim(tokens)
    if not tokens:
        return None
    compounds: list[_CSSCompoundSelector] = []
    combinators: list[str] = []
    cursor = 0
    while cursor < len(tokens):
        start = cursor
        while (
            cursor < len(tokens)
            and tokens[cursor].kind != "whitespace"
            and not (tokens[cursor].kind == "delim"
                     and tokens[cursor].value == ">")
        ):
            cursor += 1
        compound = _css_parse_compound_selector(tokens[start:cursor])
        if compound is None:
            return None
        compounds.append(compound)
        if cursor >= len(tokens):
            break
        had_whitespace = False
        while cursor < len(tokens) and tokens[cursor].kind == "whitespace":
            had_whitespace = True
            cursor += 1
        if (
            cursor < len(tokens)
            and tokens[cursor].kind == "delim"
            and tokens[cursor].value == ">"
        ):
            combinators.append("child")
            cursor += 1
            while cursor < len(tokens) and tokens[cursor].kind == "whitespace":
                cursor += 1
        elif had_whitespace:
            combinators.append("descendant")
        else:
            return None
        if cursor >= len(tokens):
            return None
    if len(combinators) != len(compounds) - 1:
        return None
    id_count = sum(len(compound.ids) for compound in compounds)
    class_count = sum(
        len(compound.classes) + int(compound.root)
        for compound in compounds
    )
    type_count = sum(compound.tag is not None for compound in compounds)
    return _CSSSelector(
        tuple(compounds), tuple(combinators),
        (0, id_count, class_count, type_count),
    )


def _css_rule_block_end(
        tokens: tuple[_CSSToken, ...], start: int
) -> int | None:
    if start >= len(tokens) or tokens[start].kind != "lbrace":
        return None
    stack = ["lbrace"]
    pairs = {"rparen": {"function", "lparen"},
             "rbracket": {"lbracket"}, "rbrace": {"lbrace"}}
    for index in range(start + 1, len(tokens)):
        token = tokens[index]
        if token.kind in _CSS_OPEN_KINDS:
            stack.append(token.kind)
        elif token.kind in _CSS_CLOSE_KINDS:
            if not stack or stack[-1] not in pairs[token.kind]:
                return None
            stack.pop()
            if not stack:
                return index
    return None


def _css_group_at_rule_is_active(
        prelude: tuple[_CSSToken, ...]
) -> bool:
    meaningful = tuple(token for token in prelude
                       if token.kind != "whitespace")
    if (
        len(meaningful) < 2
        or meaningful[0].kind != "delim"
        or meaningful[0].value != "@"
        or meaningful[1].kind != "ident"
    ):
        return False
    name = _ascii_lower(meaningful[1].value)
    if name != "media":
        return False
    rows = _css_split_top_level(prelude[2:], "comma")
    if rows is None:
        return False
    for row in rows:
        words = [
            _ascii_lower(token.value) for token in row
            if token.kind == "ident"
        ]
        if not words:
            return True  # feature-only media query may match a screen
        if words[0] == "only":
            words = words[1:]
            if not words:
                continue
        if words[0] == "not":
            if len(words) > 1 and words[1] in {"all", "screen"}:
                continue
            return True
        if words[0] in {"all", "screen"}:
            return True
        if words[0] not in {"print", "speech"}:
            return True
    return False


def _css_stylesheet_rules_from_tokens(
        tokens: tuple[_CSSToken, ...], *, order_start: int = 0
) -> tuple[list[_CSSStyleRule], int]:
    rules: list[_CSSStyleRule] = []
    cursor = 0
    order = order_start
    while cursor < len(tokens):
        while cursor < len(tokens) and tokens[cursor].kind in {
            "whitespace", "semicolon"
        }:
            cursor += 1
        if cursor >= len(tokens):
            break
        prelude_start = cursor
        stack: list[str] = []
        block_start: int | None = None
        terminated = False
        pairs = {"rparen": {"function", "lparen"},
                 "rbracket": {"lbracket"}}
        while cursor < len(tokens):
            token = tokens[cursor]
            if token.kind in {"function", "lparen", "lbracket"}:
                stack.append(token.kind)
            elif token.kind in {"rparen", "rbracket"}:
                if not stack or stack[-1] not in pairs[token.kind]:
                    terminated = True
                    break
                stack.pop()
            elif not stack and token.kind == "semicolon":
                cursor += 1
                terminated = True
                break
            elif not stack and token.kind == "lbrace":
                block_start = cursor
                break
            cursor += 1
        if terminated:
            continue
        if block_start is None:
            break
        block_end = _css_rule_block_end(tokens, block_start)
        if block_end is None:
            break
        prelude = _css_trim(tokens[prelude_start:block_start])
        block = tokens[block_start + 1:block_end]
        cursor = block_end + 1
        meaningful = tuple(token for token in prelude
                           if token.kind != "whitespace")
        if not meaningful:
            order += len(block) + 1
            continue
        if meaningful[0].kind == "delim" and meaningful[0].value == "@":
            if _css_group_at_rule_is_active(prelude):
                nested, order = _css_stylesheet_rules_from_tokens(
                    block, order_start=order)
                rules.extend(nested)
            else:
                order += len(block) + 1
            continue
        selector_rows = _css_split_top_level(prelude, "comma")
        if selector_rows is None:
            order += len(block) + 1
            continue
        declarations = _css_parse_declarations(block, order_start=order)
        order += len(block) + 1
        if not declarations:
            continue
        for selector_tokens in selector_rows:
            selector = _css_parse_selector(selector_tokens)
            if selector is None:
                continue
            rules.append(_CSSStyleRule(
                selector,
                tuple(_CSSDeclaration(
                    declaration.name, declaration.value,
                    declaration.important, declaration.order,
                    selector.specificity,
                ) for declaration in declarations),
            ))
    return rules, order


def _css_stylesheet_rules(
        source: str, *, order_start: int = 0
) -> tuple[list[_CSSStyleRule], int]:
    tokens = _css_tokens(source)
    if tokens is None:
        return [], order_start
    return _css_stylesheet_rules_from_tokens(tokens, order_start=order_start)


def _css_compound_matches(
        compound: _CSSCompoundSelector, element: ET.Element,
        parent_map: dict[ET.Element, ET.Element],
) -> bool:
    namespace, local = _dom_name(element.tag)
    if namespace != _HTML_NAMESPACE:
        return False
    if compound.tag is not None and _ascii_lower(local) != compound.tag:
        return False
    attrs = element.attrib
    if any(attrs.get("id", "") != identifier for identifier in compound.ids):
        return False
    classes = frozenset(_html_ascii_split(attrs.get("class", "")))
    if any(class_name not in classes for class_name in compound.classes):
        return False
    if compound.root and element in parent_map:
        return False
    return True


def _css_selector_matches(
        selector: _CSSSelector, element: ET.Element,
        parent_map: dict[ET.Element, ET.Element],
) -> bool:
    index = len(selector.compounds) - 1
    current = element
    if not _css_compound_matches(
            selector.compounds[index], current, parent_map):
        return False
    while index > 0:
        combinator = selector.combinators[index - 1]
        index -= 1
        parent = parent_map.get(current)
        if combinator == "child":
            if parent is None or not _css_compound_matches(
                    selector.compounds[index], parent, parent_map):
                return False
            current = parent
            continue
        while parent is not None and not _css_compound_matches(
                selector.compounds[index], parent, parent_map):
            parent = parent_map.get(parent)
        if parent is None:
            return False
        current = parent
    return True


def _css_style_element_is_active(
        element: ET.Element, parent_map: dict[ET.Element, ET.Element]
) -> bool:
    namespace, local = _dom_name(element.tag)
    if namespace != _HTML_NAMESPACE or local != "style":
        return False
    type_value = _ascii_lower(_html_ascii_strip(
        element.attrib.get("type", "")))
    if type_value not in {"", "text/css"}:
        return False
    media = _ascii_lower(_html_ascii_strip(element.attrib.get("media", "")))
    if media:
        queries = [_html_ascii_strip(row) for row in media.split(",")]
        if not any(query in {"all", "screen"}
                   or query.startswith(("all and ", "screen and "))
                   for query in queries):
            return False
    ancestor = parent_map.get(element)
    while ancestor is not None:
        ancestor_namespace, ancestor_local = _dom_name(ancestor.tag)
        if (ancestor_namespace != _HTML_NAMESPACE
                or ancestor_local in _INERT_ANCESTORS):
            return False
        ancestor = parent_map.get(ancestor)
    return True


def _css_document_rules(
        root: ET.Element, parent_map: dict[ET.Element, ET.Element]
) -> tuple[list[_CSSStyleRule], int]:
    rules: list[_CSSStyleRule] = []
    order = 0
    for element in root.iter():
        if not _css_style_element_is_active(element, parent_map):
            continue
        parsed, order = _css_stylesheet_rules(element.text or "",
                                              order_start=order)
        rules.extend(parsed)
    return rules, order


def _css_element_candidates(
        element: ET.Element, rules: list[_CSSStyleRule],
        parent_map: dict[ET.Element, ET.Element], inline_order: int,
) -> dict[str, list[_CSSDeclaration]]:
    declarations: list[_CSSDeclaration] = []
    for rule in rules:
        if _css_selector_matches(rule.selector, element, parent_map):
            declarations.extend(rule.declarations)
    style = element.attrib.get("style", "")
    if style:
        tokens = _css_tokens(style)
        if tokens is not None:
            declarations.extend(_css_parse_declarations(
                tokens, order_start=inline_order,
                specificity=(1, 0, 0, 0)))
    return _css_candidates(declarations)


def _css_candidates(
        declarations: list[_CSSDeclaration] | tuple[_CSSDeclaration, ...]
) -> dict[str, list[_CSSDeclaration]]:
    candidates: dict[str, list[_CSSDeclaration]] = {}
    for declaration in declarations:
        candidates.setdefault(declaration.name, []).append(declaration)
    return {
        name: sorted(rows, key=lambda row: (
            row.important, row.specificity, row.order), reverse=True)
        for name, rows in candidates.items()
    }


def _style_rendering_from_candidates(
        candidates: dict[str, list[_CSSDeclaration]],
        inherited_custom: dict[str, tuple[_CSSToken, ...]] | None = None,
) -> tuple[bool, str | None, dict[str, tuple[_CSSToken, ...]]]:
    """Return hard hiding, visibility override, and inherited custom values.

    ``visibility`` is deliberately separate from hard hiding: CSS permits a
    descendant with ``visibility:visible`` inside a hidden ancestor.  HTML
    hidden/inert state, display:none, zero opacity, content-visibility:hidden,
    closed dialogs/details/popovers cannot be overridden by descendants.
    """
    inherited = dict(inherited_custom or {})
    custom = dict(inherited)
    for name, rows in candidates.items():
        if name.startswith("--") and rows:
            custom_value = rows[0].value
            keyword = _css_single_ident(custom_value)
            if keyword == "initial":
                # The initial value of a custom property is guaranteed-invalid,
                # so var() must use its fallback (if any).
                custom.pop(name, None)
            elif keyword in {"inherit", "unset", "revert", "revert-layer"}:
                # Custom properties inherit; unset therefore behaves as inherit.
                if name in inherited:
                    custom[name] = inherited[name]
                else:
                    custom.pop(name, None)
            else:
                custom[name] = custom_value

    resolved: dict[str, str] = {}
    computed_opacity: float | None = None
    forced_hidden = False
    for name in ("display", "visibility", "opacity", "content-visibility"):
        for declaration in candidates.get(name, ()):
            try:
                candidate = _resolve_css_vars(declaration.value, custom)
            except _CSSLimitExceeded:
                # A bounded checker cannot prove a value that expands beyond
                # the document-sized cap.  For rendering evidence the only
                # safe outcome is to withhold that element.
                forced_hidden = True
                break
            if candidate is None:
                continue
            if name == "display":
                normal = _css_keyword_sequence(candidate)
                if normal is None:
                    continue
                valid = _display_value_is_valid(normal)
            elif name == "visibility":
                normal = _css_keyword_sequence(candidate)
                if normal is None:
                    continue
                valid = normal in (
                    _CSS_WIDE_VALUES | {"collapse", "hidden", "visible"})
            elif name == "content-visibility":
                normal = _css_keyword_sequence(candidate)
                if normal is None:
                    continue
                valid = normal in (
                    _CSS_WIDE_VALUES | {"auto", "hidden", "visible"})
            else:
                normal = "opacity"
                valid, computed_opacity, unknown_hidden = (
                    _opacity_computed_value(candidate)
                )
                forced_hidden = forced_hidden or unknown_hidden
            if valid:
                resolved[name] = normal
                break
        if forced_hidden:
            break
    display = resolved.get("display", "")
    visibility_value = resolved.get("visibility", "")
    opacity = resolved.get("opacity", "")
    content_visibility = resolved.get("content-visibility", "")
    visibility = (
        "visible" if visibility_value in {"visible", "initial"}
        else "hidden" if visibility_value in {"hidden", "collapse"}
        else None
    )
    hard_hidden = (
        forced_hidden
        or
        display == "none"
        or content_visibility == "hidden"
        or (opacity != "" and computed_opacity is not None
            and computed_opacity <= 0.0)
    )
    return hard_hidden, visibility, custom


def _inline_style_rendering(
        value: str,
        inherited_custom: dict[str, tuple[_CSSToken, ...]] | None = None,
) -> tuple[bool, str | None, dict[str, tuple[_CSSToken, ...]]]:
    inherited = dict(inherited_custom or {})
    if not isinstance(value, str) or not value:
        return False, None, inherited
    tokens = _css_tokens(value)
    if tokens is None:
        return True, None, inherited
    return _style_rendering_from_candidates(
        _css_candidates(_css_parse_declarations(
            tokens, specificity=(1, 0, 0, 0))), inherited)


def _inline_style_hides(value: str) -> bool:
    """Compatibility predicate for one element's own inline declaration."""
    hard_hidden, visibility, _custom = _inline_style_rendering(value)
    return hard_hidden or visibility == "hidden"


def _element_hides_rendered_content(element: ET.Element) -> bool:
    attrs = element.attrib
    style_hard, style_visibility, _custom = _inline_style_rendering(
        attrs.get("style", ""))
    return (
        "hidden" in attrs
        or "inert" in attrs
        or "popover" in attrs
        or _ascii_lower(_html_ascii_strip(
            attrs.get("aria-hidden", ""))) == "true"
        or style_hard
        or style_visibility == "hidden"
    )


def _element_text(
        element: ET.Element, *, text_visible: dict[ET.Element, bool] | None = None,
        tail_visible: dict[ET.Element, bool] | None = None) -> str:
    """Return projected rendered text, preserving only visible sibling tails."""
    pieces: list[str] = []
    if element.text and (text_visible is None or text_visible.get(element, False)):
        pieces.append(element.text)
    stack: list[tuple[ET.Element, bool]] = [
        (child, True) for child in reversed(list(element))
    ]
    while stack:
        node, entering = stack.pop()
        if entering:
            _namespace, local = _dom_name(node.tag)
            if text_visible is None and local in _INERT_ANCESTORS:
                if node.tail:
                    pieces.append(node.tail)
                continue
            if node.text and (
                    text_visible is None or text_visible.get(node, False)):
                pieces.append(node.text)
            stack.append((node, False))
            for child in reversed(list(node)):
                stack.append((child, True))
        elif node.tail and (
                tail_visible is None or tail_visible.get(node, False)):
            pieces.append(node.tail)
    return " ".join("".join(pieces).split())


@dataclass
class _PageDocument:
    """Security policy projected from one standards-compliant HTML5 DOM.

    html5lib owns tokenisation and tree construction, including duplicate
    attributes, script double-escaped states, insertion modes, integration
    points, implicit closes, and EOF recovery.  This class deliberately owns
    only the checker's stable policy: evidence must be in the effective HTML
    head/body, outside inert or foreign ancestry, and satisfy the explicit
    URL/JSON-LD contracts below.
    """

    title: str = ""
    description_values: list[str] = field(default_factory=list)
    h1_values: list[str] = field(default_factory=list)
    h1_element_count: int = 0
    base_href: str | None = None
    canonical_hrefs: list[str] = field(default_factory=list)
    json_ld_blocks: list[tuple[str, str]] = field(default_factory=list)
    source_has_nul: bool = False


def _parse_page_document_in_process(source: str) -> _PageDocument:
    """Parse and project facts inside the disposable parser child only."""
    if getattr(html5lib, "__version__", None) != "1.1":
        raise RuntimeError(
            "advisorsai-check requires html5lib==1.1; reinstall the package")
    parser = html5lib.HTMLParser(
        tree=html5lib.getTreeBuilder("etree"),
        namespaceHTMLElements=True,
        strict=False,
    )
    root = parser.parse(source, scripting=True)
    # HTML tokenisation replaces a literal NUL with U+FFFD.  Preserve the raw
    # fact so that replacement cannot turn an unsafe JSON-LD name into visible
    # evidence after parsing.
    document = _PageDocument(source_has_nul="\x00" in source)
    parent_map = {
        child: parent for parent in root.iter() for child in parent
    }
    style_rules, style_order = _css_document_rules(root, parent_map)
    inline_order = style_order + MAX_HTML_BYTES + 1
    regions: dict[ET.Element, str] = {}
    visible: dict[ET.Element, bool] = {}
    text_visible: dict[ET.Element, bool] = {}
    tail_visible: dict[ET.Element, bool] = {}
    stack: list[
        tuple[
            ET.Element, int, str, bool, bool, str,
            dict[str, tuple[_CSSToken, ...]],
        ]
    ] = [
        (root, 0, "", True, False, "visible", {})
    ]
    ordered: list[ET.Element] = []
    while stack:
        (element, depth, inherited_region, pure_html_ancestry,
         inherited_hard_hidden, inherited_visibility,
         inherited_custom) = stack.pop()
        if depth > MAX_HTML_DOM_DEPTH:
            raise ValueError("HTML DOM exceeds the parser depth limit")
        namespace, local = _dom_name(element.tag)
        pure_html = pure_html_ancestry and namespace == _HTML_NAMESPACE
        region = inherited_region if pure_html else ""
        if pure_html and local in {"head", "body"}:
            region = local
        regions[element] = region
        attrs = element.attrib
        style_hard, visibility_override, element_custom = (
            _style_rendering_from_candidates(
                _css_element_candidates(
                    element, style_rules, parent_map, inline_order),
                inherited_custom,
            )
        )
        css_visibility = visibility_override or inherited_visibility
        element_hard_hidden = (
            inherited_hard_hidden
            or not pure_html
            or local in _INERT_ANCESTORS
            or "hidden" in attrs
            or "inert" in attrs
            or "popover" in attrs
            or _ascii_lower(_html_ascii_strip(
                attrs.get("aria-hidden", ""))) == "true"
            or style_hard
            or (local == "dialog" and "open" not in attrs)
        )
        element_visible = (
            not element_hard_hidden and css_visibility == "visible")
        visible[element] = element_visible
        closed_details = (
            pure_html and local == "details" and "open" not in attrs)
        text_visible[element] = element_visible and not closed_details
        ordered.append(element)
        child_region = (
            region if pure_html and local not in _INERT_ANCESTORS else "")
        children = list(element)
        first_summary = next((
            child for child in children
            if _dom_name(child.tag) == (_HTML_NAMESPACE, "summary")
        ), None) if closed_details else None
        for child in reversed(children):
            child_hard_hidden = element_hard_hidden
            child_tail_visible = element_visible
            if closed_details:
                child_hard_hidden = (
                    element_hard_hidden or child is not first_summary)
                # A summary's following tail and every other details child are
                # part of the closed details content, not of the visible label.
                child_tail_visible = False
            tail_visible[child] = child_tail_visible
            stack.append((
                child, depth + 1, child_region, pure_html,
                child_hard_hidden, css_visibility, element_custom,
            ))

    title_seen = False
    for element in ordered:
        namespace, local = _dom_name(element.tag)
        if namespace != _HTML_NAMESPACE:
            continue
        region = regions[element]
        if not region:
            continue
        attrs = element.attrib
        if local == "title" and region == "head" and not title_seen:
            # <title> is document metadata, not rendered body evidence.  Its
            # hidden/style attributes do not change the document title.
            document.title = _element_text(element)
            title_seen = True
        elif local == "meta" and region == "head":
            if _ascii_lower(_html_ascii_strip(
                    attrs.get("name", ""))) == "description":
                document.description_values.append(
                    _html_ascii_strip(attrs.get("content", "")))
        elif local == "base":
            if document.base_href is None and "href" in attrs:
                document.base_href = _html_ascii_strip(attrs["href"])
        elif local == "link" and region == "head":
            rel_tokens = {
                _ascii_lower(token)
                for token in _html_ascii_split(attrs.get("rel", ""))
            }
            if "canonical" in rel_tokens:
                document.canonical_hrefs.append(
                    _html_ascii_strip(attrs.get("href", "")))
        elif local == "h1" and region == "body" and visible[element]:
            document.h1_element_count += 1
            document.h1_values.append(_element_text(
                element, text_visible=text_visible, tail_visible=tail_visible))
        elif local == "script":
            if (_ascii_lower(_html_ascii_strip(attrs.get("type", "")))
                    == "application/ld+json"):
                document.json_ld_blocks.append((element.text or "", region))
    return document


_PAGE_DOCUMENT_KEYS = frozenset({
    "title", "description_values", "h1_values", "h1_element_count",
    "base_href", "canonical_hrefs", "json_ld_blocks", "source_has_nul",
})


def _page_document_payload(document: _PageDocument) -> dict[str, object]:
    return {
        "title": document.title,
        "description_values": document.description_values,
        "h1_values": document.h1_values,
        "h1_element_count": document.h1_element_count,
        "base_href": document.base_href,
        "canonical_hrefs": document.canonical_hrefs,
        "json_ld_blocks": [list(item) for item in document.json_ld_blocks],
        "source_has_nul": document.source_has_nul,
    }


def _page_document_from_payload(payload: object) -> _PageDocument:
    if not isinstance(payload, dict) or set(payload) != _PAGE_DOCUMENT_KEYS:
        raise ValueError("parser child returned an invalid fact object")
    string_lists = ("description_values", "h1_values", "canonical_hrefs")
    if not isinstance(payload["title"], str) or any(
        not isinstance(payload[key], list)
        or any(not isinstance(item, str) for item in payload[key])
        for key in string_lists
    ):
        raise ValueError("parser child returned invalid text facts")
    base_href = payload["base_href"]
    if base_href is not None and not isinstance(base_href, str):
        raise ValueError("parser child returned an invalid base fact")
    count = payload["h1_element_count"]
    if type(count) is not int or count < 0:  # bool is not a valid count
        raise ValueError("parser child returned an invalid heading count")
    source_has_nul = payload["source_has_nul"]
    if type(source_has_nul) is not bool:
        raise ValueError("parser child returned an invalid source fact")
    blocks = payload["json_ld_blocks"]
    if not isinstance(blocks, list) or any(
        not isinstance(item, list)
        or len(item) != 2
        or any(not isinstance(value, str) for value in item)
        for item in blocks
    ):
        raise ValueError("parser child returned invalid JSON-LD facts")
    return _PageDocument(
        title=payload["title"],
        description_values=list(payload["description_values"]),
        h1_values=list(payload["h1_values"]),
        h1_element_count=count,
        base_href=base_href,
        canonical_hrefs=list(payload["canonical_hrefs"]),
        json_ld_blocks=[(item[0], item[1]) for item in blocks],
        source_has_nul=source_has_nul,
    )


def _parse_page_document(
        source: str, *, deadline: float | None = None) -> _PageDocument:
    """Run standards parsing and fact extraction in a killable child.

    The parent performs only a byte cap.  It never guesses HTML tokens,
    nesting, raw-text state, or browser error recovery.  The pinned html5lib
    parser is the sole HTML authority; a hard wall clock and process boundary
    contain pathological inputs without rejecting valid sibling-heavy pages.
    """
    if not isinstance(source, str):
        raise TypeError("HTML source must be text")
    try:
        raw = source.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError("HTML source contains an invalid Unicode scalar") from exc
    if len(raw) > MAX_HTML_BYTES:
        raise ValueError("HTML source exceeds the parser byte limit")
    hard_deadline = time.monotonic() + HTML_PARSE_TIMEOUT
    if deadline is not None:
        hard_deadline = min(hard_deadline, deadline)
    timeout = _remaining(hard_deadline)
    process = subprocess.Popen(
        [sys.executable, "-I", str(Path(__file__).resolve()),
         "--html-parse-child"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, _stderr = process.communicate(input=raw, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise ValueError("HTML parser deadline exceeded") from exc
    if process.returncode != 0:
        raise ValueError("HTML parser child rejected the document")
    if len(stdout) > MAX_HTML_FACT_BYTES:
        raise ValueError("HTML parser facts exceed the output limit")
    try:
        payload = json.loads(
            stdout.decode("utf-8", "strict"),
            object_pairs_hook=_json_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("HTML parser child returned malformed facts") from exc
    return _page_document_from_payload(payload)


_SITEMAP_NAMESPACE = "http://www.sitemaps.org/schemas/sitemap/0.9"


def _xml_name(tag: object) -> tuple[str, str]:
    if not isinstance(tag, str):
        return "", ""
    if tag.startswith("{") and "}" in tag:
        namespace, local = tag[1:].split("}", 1)
        return namespace, local
    return "", tag


def _public_web_authority(value: str) -> tuple[str, str, int] | None:
    """Return a strict public-web authority without performing DNS I/O.

    Canonicals and sitemap locations share this exact parser.  It rejects
    ambiguous legacy IPv4 spellings understood by ``inet_aton`` (hex, octal,
    shortened, or mixed components), local/reserved authorities, malformed
    DNS labels, and invalid punycode before either caller applies its own
    cross-site policy.
    """
    if not value or len(value) > MAX_URL_CHARS:
        return None
    if (any(
            character.isspace() or unicodedata.category(character) == "Cc"
            for character in value)
            or re.search(r"%(?![0-9a-fA-F]{2})", value)
            or any(character in '<>"{}|\\^`' for character in value)):
        return None
    try:
        parsed = urlsplit(value)
        scheme = _ascii_lower(parsed.scheme)
        port = parsed.port or (443 if scheme == "https" else 80)
        raw_authority = parsed.netloc
        raw_host = parsed.hostname or ""
    except (UnicodeError, ValueError):
        return None
    if (
        scheme not in {"http", "https"}
        or not raw_authority
        or not raw_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {80, 443}
        or "%" in raw_authority
        or any(ord(character) > 127 for character in raw_authority)
    ):
        return None

    host = _ascii_lower(raw_host)
    if (
        not host
        or host.endswith(".")
        or host == "localhost"
        or host.endswith((
            ".localhost", ".local", ".localdomain", ".internal", ".lan",
            ".home.arpa", ".test", ".invalid", ".example", ".onion",
        ))
    ):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # POSIX/Windows resolvers still accept forms that ipaddress correctly
        # refuses, including 0x7f.1 and 0177.0.0.1.  A canonical identity or
        # sitemap location must never carry that ambiguity.
        try:
            socket.inet_aton(host)
        except OSError:
            pass
        else:
            return None
        if len(host) > 253 or "." not in host:
            return None
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label,
            ) is None
            for label in labels
        ):
            return None
        for label in labels:
            if not label.startswith("xn--"):
                continue
            try:
                decoded = label.encode("ascii").decode("idna")
                round_trip = decoded.encode("idna").decode("ascii")
            except (UnicodeError, ValueError):
                return None
            if _ascii_lower(round_trip) != label or any(
                separator in decoded
                for separator in (".", "\u3002", "\uff0e", "\uff61")
            ):
                return None
    else:
        if not address.is_global:
            return None
    return scheme, host, port


def _valid_http_location(value: str) -> bool:
    return _public_web_authority(value) is not None


def _valid_canonical_location(value: str) -> bool:
    """Accept an absolute public-web canonical, including another domain.

    Canonicals describe identity; they are not fetched here.  Still, treating a
    loopback/private literal or a local hostname as a valid public identity is
    both misleading and unsafe for downstream consumers that may follow it.
    Validate the host syntactically without imposing a same-origin rule: a
    legitimate cross-domain migration remains valid.
    """
    if _public_web_authority(value) is None:
        return False
    # Encoded path separators and control octets are ambiguous to downstream
    # crawlers/proxies even though they are outside the authority.
    for match in _PERCENT_OCTET.finditer(value):
        octet = int(match.group(1), 16)
        if octet <= 0x20 or octet == 0x7F or octet in {0x2F, 0x5C}:
            return False
    return True


def _effective_document_base(
        request_url: str, declared_href: str | None) -> str | None:
    """Return the same-origin public HTML document base, or fail closed.

    A relative canonical is resolved by browsers against the first active
    ``<base href>`` in document tree order, including an active body element.
    Letting a private or cross-origin base alter
    that resolution would make the checker attest a different identity from
    the submitted public page.  An absent base uses the fetched URL; a present
    but unsafe base invalidates the canonical signal instead of being ignored.
    """
    request_authority = _public_web_authority(request_url)
    if (
        request_authority is None
        or not _valid_canonical_location(request_url)
    ):
        return None
    if declared_href is None:
        return request_url
    resolved = urljoin(request_url, declared_href)
    return resolved if (
        _public_web_authority(resolved) == request_authority
        and _valid_canonical_location(resolved)
    ) else None


def _valid_sitemap_record(
        record: ET.Element, namespace: str, expected_record: str, *,
        expected_authority: tuple[str, str, int]) -> bool:
    record_namespace, record_name = _xml_name(record.tag)
    if (record_namespace, record_name) != (namespace, expected_record):
        return False
    locations = [
        child for child in list(record)
        if _xml_name(child.tag) == (namespace, "loc")
    ]
    if len(locations) != 1:
        return False
    location = locations[0]
    # A loc containing nested markup is not a location string.
    value = (location.text or "").strip()
    return (
        not list(location)
        and _public_web_authority(value) == expected_authority
    )


_SCHEMA_CONTEXTS = frozenset({
    "http://schema.org", "http://schema.org/",
    "https://schema.org", "https://schema.org/",
})


def _schema_context_is_exact(value: object) -> bool:
    """Accept only contexts whose vocabulary is unambiguously schema.org."""
    if isinstance(value, str):
        return value in _SCHEMA_CONTEXTS
    if isinstance(value, dict):
        return (
            set(value) == {"@vocab"}
            and value.get("@vocab") in _SCHEMA_CONTEXTS
        )
    if isinstance(value, list):
        return bool(value) and all(_schema_context_is_exact(item) for item in value)
    return False


def _schema_type_name(value: str) -> str:
    # Schema type identifiers are exact JSON strings.  Unicode-aware trimming
    # would promote ``Organization\u00a0`` to a different, valid identifier.
    candidate = value
    for prefix in _SCHEMA_CONTEXTS:
        iri_prefix = prefix if prefix.endswith("/") else prefix + "/"
        if candidate.startswith(iri_prefix):
            candidate = candidate[len(iri_prefix):]
            break
    return candidate if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", candidate) else ""


_UNSAFE_VISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Co", "Cs"})


def _meaningful_visible_text(value: object) -> str:
    """Return normalised visible text, or empty for unsafe/meaningless text.

    A trusted label needs at least one Unicode letter or number after NFKC.
    Marks, emoji variation selectors and punctuation alone are not names.  A
    single control, format/bidi, surrogate, private-use, or unassigned scalar
    invalidates the whole value rather than silently changing its identity.
    """
    if not isinstance(value, str) or not value:
        return ""
    normalised = unicodedata.normalize("NFKC", value)
    categories = [unicodedata.category(character) for character in normalised]
    if any(category in _UNSAFE_VISIBLE_CATEGORIES for category in categories):
        return ""
    if not any(category[0] in {"L", "N"} for category in categories):
        return ""
    return " ".join(normalised.split())


def _safe_visible_jsonld_name(value: object) -> bool:
    return bool(_meaningful_visible_text(value))


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _json_object_without_duplicates(
        pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object member")
        result[key] = value
    return result


_HOME_DERIVED_SIGNALS = (
    ("title", 1),
    ("description", 1),
    ("structured_business", 2),
    ("structured_offering", 2),
    ("h1", 1),
    ("canonical", 1),
)


def _terminal_home_stage(
        home_ok: bool | None, detail: str) -> list[Signal]:
    """Emit every required home-stage receipt on terminal page failure."""
    derived_ok = False if home_ok is False else None
    derived_detail = (
        "the page representation is unavailable for this check"
        if derived_ok is None else
        "the page representation does not provide this checked field"
    )
    return [
        Signal("home", home_ok, detail, SIGNAL_WEIGHT_CONTRACT["home"]),
        *[
            Signal(key, derived_ok, derived_detail, weight)
            for key, weight in _HOME_DERIVED_SIGNALS
        ],
    ]


def check_home(base: str, *, deadline: float | None = None) -> list[Signal]:
    result = _get(base, deadline=deadline)
    status, html = result
    if status == 0:
        return _terminal_home_stage(
            None, f"the home page could not be read (HTTP {status})")
    if status != 200:
        return _terminal_home_stage(
            False, f"the submitted page returned HTTP {status}; only a full "
                   "HTTP 200 representation is accepted")
    type_ok, _charset = _content_type(result, frozenset({"text/html"}))
    if not type_ok:
        return _terminal_home_stage(
            False, "the submitted page was not served as text/html")
    if not html:
        return _terminal_home_stage(
            False, "the submitted page returned an empty HTML body")
    out = [Signal("home", True, f"home page reachable (HTTP {status})", 0)]

    try:
        document = _parse_page_document(html, deadline=deadline)
    except (AssertionError, TypeError, ValueError):
        return _terminal_home_stage(
            None, "the home page HTML could not be parsed")

    text = _meaningful_visible_text(document.title)
    out.append(Signal("title", bool(text) and len(text) > 10,
                      f"page title: «{text[:70]}»" if text
                      else "no <title>: the assistant has no name for the page",
                      1))

    dtext = next((
        text for value in document.description_values
        if (text := _meaningful_visible_text(value))
    ), "")
    out.append(Signal("description", len(dtext) >= 50,
                      f"meta description, {len(dtext)} chars" if dtext
                      else "no meta description",
                      1))

    named_types: set[str] = set()
    invalid_type = False
    invalid_context = False
    invalid_json = False
    for block, _region in document.json_ld_blocks:
        try:
            data = json.loads(
                block,
                object_pairs_hook=_json_object_without_duplicates,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, RecursionError, ValueError):
            invalid_json = True
            continue
        inherited_context: object = None
        if isinstance(data, dict):
            inherited_context = data.get("@context")
            graph = data.get("@graph")
            nodes = graph if isinstance(graph, list) else [data]
        elif isinstance(data, list):
            nodes = data
        else:
            nodes = []
        for node in nodes:
            if not isinstance(node, dict) or "@type" not in node:
                continue
            context = node.get("@context", inherited_context)
            if not _schema_context_is_exact(context):
                invalid_context = True
                continue
            raw_type = node.get("@type")
            if isinstance(raw_type, str):
                types = [raw_type]
            elif isinstance(raw_type, list):
                types = [item for item in raw_type if isinstance(item, str)]
                invalid_type = invalid_type or len(types) != len(raw_type)
            else:
                types = []
                invalid_type = True
            if (not document.source_has_nul
                    and _safe_visible_jsonld_name(node.get("name"))):
                accepted_types = {
                    result for item in types
                    if (result := _schema_type_name(item))
                }
                named_types.update(accepted_types)
    invalid_reasons: list[str] = []
    if invalid_json:
        invalid_reasons.append("a JSON-LD block does not parse")
    if invalid_context:
        invalid_reasons.append(
            "a JSON-LD @context is missing or not schema.org")
    if invalid_type:
        invalid_reasons.append("a JSON-LD @type is not text")
    if invalid_reasons:
        out.append(Signal(
            "jsonld_valid", False,
            "; ".join(invalid_reasons) + "; invalid machine data was ignored",
            1))
    business = {"Organization", "LocalBusiness", "Corporation", "Store",
                "ProfessionalService"} & named_types
    out.append(Signal("structured_business", bool(business),
                      f"structured data identifies the business ({', '.join(sorted(business))})"
                      if business else
                      "no Organization/LocalBusiness structured data: nothing "
                      "states what this business IS in a form machines read",
                      2))
    # JSON-LD is active machine-readable HTML metadata in either the effective
    # head or body.  Only visible HTML evidence such as h1 is body-only.
    offering = {
        "Service", "Product", "Offer", "OfferCatalog",
    } & named_types
    out.append(Signal("structured_offering", bool(offering),
                      f"structured data names what you sell ({', '.join(sorted(offering))})"
                      if offering else
                      "no Service/Product structured data: what you sell is "
                      "only in prose",
                      2))

    h1_text = [
        text for value in document.h1_values
        if (text := _meaningful_visible_text(value))
    ]
    one_h1 = document.h1_element_count == 1 and len(h1_text) == 1
    out.append(Signal("h1", one_h1,
                      f"one <h1>: «{h1_text[0][:60]}»" if one_h1
                      else f"{document.h1_element_count} <h1> elements"
                           if h1_text else "no <h1>",
                      1))

    canonical = ""
    document_base = _effective_document_base(base, document.base_href)
    if document_base is not None and len(document.canonical_hrefs) == 1:
        candidate = document.canonical_hrefs[0]
        resolved = urljoin(document_base, candidate)
        if (
            candidate
            and _valid_canonical_location(resolved)
            and _public_web_authority(resolved) == _public_web_authority(base)
        ):
            canonical = candidate
    out.append(Signal("canonical", bool(canonical),
                      "canonical link with an HTTP(S) href is present"
                      if canonical else "no canonical link with a valid href", 1))
    return out


def run(url: str) -> Report:
    deadline = time.monotonic() + TIMEOUT
    base = normalise(url)
    # Resolve once before constructing a report so an unsafe address is a
    # rejected request, not a misleading report with several unchecked rows.
    _canonical, host, port, _target, _header = _canonical_target(base)
    _resolve_public(host, port, deadline=deadline)
    report = Report(url=base)
    checks = (
        (check_home, (
            "home", "title", "description", "structured_business",
            "structured_offering", "h1", "canonical",
        )),
        (check_robots, ("robots",)),
        (check_llms_txt, ("llms_txt",)),
        (check_sitemap, ("sitemap",)),
    )

    def unavailable(keys: tuple[str, ...]) -> list[Signal]:
        return [
            Signal(
                key,
                None,
                "this checker stage did not complete",
                SIGNAL_WEIGHT_CONTRACT[key],
            )
            for key in keys
        ]

    # Run sequentially against one absolute deadline.  Every network operation
    # receives only the remaining budget and HTML parsing is process-isolated,
    # so returning from this function cannot leave an uncancellable thread or
    # parser child alive.  Completed earlier checks are retained deterministically.
    for index, (check, stage_keys) in enumerate(checks):
        try:
            _remaining(deadline)
            report.signals.extend(check(base, deadline=deadline))
        except TimeoutError:
            report.errors.append(f"{check.__name__}: TimeoutError")
            report.signals.extend(unavailable(stage_keys))
            for skipped, skipped_keys in checks[index + 1:]:
                report.errors.append(f"{skipped.__name__}: TimeoutError")
                report.signals.extend(unavailable(skipped_keys))
            break
        except Exception as exc:                          # noqa: BLE001
            report.errors.append(f"{check.__name__}: {type(exc).__name__}")
            report.signals.extend(unavailable(stage_keys))
    return report


def _html_parse_child_main() -> int:
    """Private subprocess protocol: capped UTF-8 in, capped JSON facts out."""
    raw = sys.stdin.buffer.read(MAX_HTML_BYTES + 1)
    if len(raw) > MAX_HTML_BYTES:
        return 3
    try:
        source = raw.decode("utf-8", "strict")
        document = _parse_page_document_in_process(source)
        encoded = json.dumps(
            _page_document_payload(document),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (AssertionError, TypeError, ValueError, UnicodeError):
        return 4
    if len(encoded) > MAX_HTML_FACT_BYTES:
        return 5
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


def _robots_eval_child_main() -> int:
    """Private subprocess protocol: capped JSON policy in, closed facts out."""
    raw = sys.stdin.buffer.read(_ROBOTS_CHILD_MAX_BYTES + 1)
    if len(raw) > _ROBOTS_CHILD_MAX_BYTES:
        return 3
    try:
        payload = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_json_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
        if (not isinstance(payload, dict)
                or set(payload) != {"body", "path"}
                or not isinstance(payload["body"], str)
                or not isinstance(payload["path"], str)
                or len(payload["path"]) > MAX_URL_CHARS):
            return 4
        encoded = json.dumps(
            _robots_evaluation_in_process(payload["body"], payload["path"]),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError):
        return 4
    if len(encoded) > _ROBOTS_CHILD_MAX_OUTPUT:
        return 5
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__" and sys.argv[1:] == ["--html-parse-child"]:
    raise SystemExit(_html_parse_child_main())
if __name__ == "__main__" and sys.argv[1:] == ["--robots-eval-child"]:
    raise SystemExit(_robots_eval_child_main())
