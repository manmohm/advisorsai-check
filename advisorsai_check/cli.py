"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata

from .core import run

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
_OSC = re.compile(r"\x1b\].*?(?:\x07|\x1b\\|$)", re.S)
_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ESCAPE = re.compile(r"\x1b(?:[ -/]*[@-~])?")


def _plain() -> bool:
    return not sys.stdout.isatty()


def _safe_text(value: object) -> str:
    """Remove terminal control channels from fetched or exceptional text."""
    cleaned = _OSC.sub("", str(value))
    cleaned = _CSI.sub("", cleaned)
    cleaned = _ESCAPE.sub("", cleaned)
    cleaned = "".join(
        " " if character in "\r\n\t" else character
        for character in cleaned
        if character in "\r\n\t"
        or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
    )
    return re.sub(r"\s+", " ", cleaned).strip()


def _safe_signal(signal) -> dict[str, object]:
    return {
        "key": _safe_text(signal.key),
        "ok": signal.ok,
        "detail": _safe_text(signal.detail),
        "weight": signal.weight,
        "evidence": _safe_text(signal.evidence),
    }


def render(report) -> str:
    c = (lambda s, _: s) if _plain() else (lambda s, k: f"{k}{s}{OFF}")
    lines = [c(f"advisorsai-check  {_safe_text(report.url)}", BOLD), ""]
    for s in report.signals:
        if s.weight == 0 and s.ok:
            continue
        if s.weight == 0:
            mark, colour = "note", DIM
        else:
            mark = "ok  " if s.ok else ("--  " if s.ok is None else "MISS")
            colour = GREEN if s.ok else (DIM if s.ok is None else RED)
        lines.append(f"  {c(mark, colour)} {_safe_text(s.detail)}")
    if report.errors:
        lines.append("")
        for error in report.errors:
            lines.append(f"  {c('ERROR', RED)} {_safe_text(error)}")
    if report.score is None:
        lines += ["", c(
            "  No complete score is published for this partial run; "
            f"{report.coverage_percent}% of weighted checks returned a result.",
            BOLD,
        )]
    else:
        lines += ["", c(f"  {report.score}% of the declared public-page basics "
                        f"are in place.", BOLD)]
    if report.unchecked:
        lines.append(c(f"  ({len(report.unchecked)} check(s) could not run "
                       "and are excluded from the score, not failed.)", DIM))
    if not report.successful:
        lines.append(c(
            "  RESULT INCOMPLETE: one or more checks were unavailable or failed internally; this run is unsuccessful.",
            RED))
    lines += [
        "",
        c("  What this is: a bounded fetch of declared page, robots, structured-data, and sitemap basics.", DIM),
        c("  What it is not: proof that an official crawler passed a firewall, or that an assistant names you.", DIM),
        c("  Live answer visibility takes timestamped captures against real assistants.", DIM),
        c("  against real assistants: https://advisorsai.ai", DIM),
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="advisorsai-check",
        description="Check bounded machine-readable basics on a public page.")
    ap.add_argument("url", help="your site, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)
    try:
        report = run(args.url)
    except ValueError as exc:
        print(f"error: {_safe_text(exc)}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({
            "url": _safe_text(report.url),
            "success": report.successful,
            "score": report.score,
            "coverage_percent": report.coverage_percent,
            "unchecked_count": len(report.unchecked),
            "signals": [_safe_signal(s) for s in report.signals],
            "errors": [_safe_text(error) for error in report.errors],
        }, ensure_ascii=False, indent=2))
    else:
        print(render(report))
    return 0 if report.successful else 1


if __name__ == "__main__":
    raise SystemExit(main())
