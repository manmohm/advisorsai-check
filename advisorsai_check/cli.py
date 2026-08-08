"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from .core import run

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def _plain() -> bool:
    return not sys.stdout.isatty()


def render(report) -> str:
    c = (lambda s, _: s) if _plain() else (lambda s, k: f"{k}{s}{OFF}")
    lines = [c(f"advisorsai-check  {report.url}", BOLD), ""]
    for s in report.signals:
        if s.weight == 0 and s.ok:
            continue
        mark = "ok  " if s.ok else ("--  " if s.ok is None else "MISS")
        colour = GREEN if s.ok else (DIM if s.ok is None else RED)
        lines.append(f"  {c(mark, colour)} {s.detail}")
    lines += ["", c(f"  {report.score}% of the machine-readability signals "
                    f"we can check from outside are in place.", BOLD)]
    if report.unchecked:
        lines.append(c(f"  ({len(report.unchecked)} check(s) could not run "
                       "and are excluded from the score, not failed.)", DIM))
    lines += [
        "",
        c("  What this is: whether machines can READ you.", DIM),
        c("  What it is not: whether an assistant NAMES you when a buyer asks.", DIM),
        c("  That one cannot be read off your HTML. It takes real captures", DIM),
        c("  against real assistants: https://advisorsai.ai", DIM),
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="advisorsai-check",
        description="Check whether AI assistants can read your website.")
    ap.add_argument("url", help="your site, e.g. example.com")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)
    try:
        report = run(args.url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({
            "url": report.url, "score": report.score,
            "signals": [vars(s) for s in report.signals],
            "errors": report.errors,
        }, ensure_ascii=False, indent=2))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
