"""Adapter-only checks through the real SDK, using offline core report fixtures."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import anyio
from mcp import Client
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from advisorsai_check import Report, Signal, core
from advisorsai_check import mcp_stdio as adapter


URL = "https://fixture.invalid/store?campaign=fixture"


def report_fixture(*, partial: bool = False) -> Report:
    """Use real Report/Signal classes and their original weight contract."""
    signals = []
    for key, weight in core.SIGNAL_WEIGHT_CONTRACT.items():
        if key == "jsonld_valid":
            continue
        ok = None if partial and key == "sitemap" else key != "description"
        signals.append(Signal(
            key=key, ok=ok, weight=weight,
            detail="Fixture \x1b[31mtitle\x1b[0m\nrow" if key == "title" else f"Fixture {key}",
            evidence="Fixture evidence",
        ))
    return Report(
        url=URL, signals=signals,
        errors=["Fixture stage unavailable"] if partial else [],
    )


class LocalMCPAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def invoke_fixture(self, report: Report) -> dict:
        # Patch only the adapter's public-library call boundary. SDK validation,
        # middleware, schema generation, serialization and core properties are real.
        with patch.object(adapter, "run", return_value=report) as measured:
            with anyio.fail_after(5):
                async with Client(adapter.mcp) as client:
                    result = await client.call_tool(adapter.TOOL_NAME, {"url": URL})
            measured.assert_called_once_with(URL)
        self.assertFalse(result.is_error)
        self.assertIsInstance(result.structured_content, dict)
        return result.structured_content

    async def test_complete_report_preserves_values_and_sanitizes_display_text(self):
        report = report_fixture()
        self.assertTrue(report.successful, "Complete fixture must satisfy the real contract")
        payload = await self.invoke_fixture(report)
        self.assertEqual(set(payload), {
            "url", "success", "score", "coverage_percent", "unchecked_count", "signals", "errors",
        })
        self.assertEqual(payload["url"], URL)  # Query is deliberately retained.
        self.assertEqual(payload["success"], report.successful)
        self.assertEqual(payload["score"], report.score)
        self.assertEqual(payload["coverage_percent"], report.coverage_percent)
        self.assertEqual(payload["unchecked_count"], len(report.unchecked))
        self.assertEqual(payload["errors"], report.errors)
        self.assertEqual(len(payload["signals"]), len(report.signals))
        for actual, expected in zip(payload["signals"], report.signals):
            self.assertEqual(set(actual), {"key", "ok", "detail", "weight", "evidence"})
            self.assertEqual(actual["key"], expected.key)
            self.assertIs(actual["ok"], expected.ok)
            self.assertEqual(actual["weight"], expected.weight)
            self.assertEqual(actual["evidence"], expected.evidence)
            self.assertNotIn("\x1b", actual["detail"])
        title = next(signal for signal in payload["signals"] if signal["key"] == "title")
        self.assertEqual(title["detail"], "Fixture title row")

    async def test_partial_report_keeps_null_score_and_unchecked_signal(self):
        report = report_fixture(partial=True)
        self.assertFalse(report.successful)
        self.assertIsNone(report.score)
        payload = await self.invoke_fixture(report)
        self.assertFalse(payload["success"])
        self.assertIsNone(payload["score"])
        self.assertEqual(payload["coverage_percent"], report.coverage_percent)
        self.assertEqual(payload["unchecked_count"], len(report.unchecked))
        self.assertEqual(payload["errors"], report.errors)
        sitemap = next(signal for signal in payload["signals"] if signal["key"] == "sitemap")
        self.assertIsNone(sitemap["ok"])

    async def test_rejected_target_returns_fixed_protocol_error(self):
        sentinel = "do-not-echo-this-input-or-exception"
        with patch.object(adapter, "run", side_effect=ValueError(sentinel)) as measured:
            with anyio.fail_after(5):
                async with Client(adapter.mcp) as client:
                    with self.assertRaises(MCPError) as caught:
                        await client.call_tool(adapter.TOOL_NAME, {"url": URL})
            measured.assert_called_once_with(URL)
        self.assertEqual(caught.exception.code, INVALID_PARAMS)
        self.assertEqual(
            caught.exception.message,
            "Target rejected or unresolved; provide one credential-free public HTTP(S) page or domain.",
        )
        self.assertNotIn(sentinel, caught.exception.message)
        self.assertNotIn(URL, caught.exception.message)

    async def test_unknown_argument_is_rejected_before_measurement(self):
        with patch.object(adapter, "run", return_value=report_fixture()) as measured:
            with anyio.fail_after(5):
                async with Client(adapter.mcp) as client:
                    with self.assertRaises(MCPError) as caught:
                        await client.call_tool(
                            adapter.TOOL_NAME, {"url": URL, "language": "en"},
                        )
            measured.assert_not_called()
        self.assertEqual(caught.exception.code, INVALID_PARAMS)


if __name__ == "__main__":
    unittest.main()
