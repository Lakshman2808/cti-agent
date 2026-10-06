"""Command-line entry point: `cti-agent investigate|extract|enrich|sources`."""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from pathlib import Path

from . import enrichment, iocs


def _load_dotenv(path: Path = Path(".env")) -> None:
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip() if not line.lstrip().startswith("#") else ""
        if "=" in line:
            key, value = line.split("=", 1)
            if value.strip():
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _fetch_report(url: str) -> str:
    r = enrichment.http().get(url)
    r.raise_for_status()
    text = r.text
    if "html" in r.headers.get("content-type", ""):
        text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", text)
        text = re.sub(r"(?s)<br\s*/?>|</p>|</div>|</li>|</h\d>|</tr>", "\n", text)
        text = html.unescape(re.sub(r"(?s)<[^>]+>", " ", text))
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def _resolve_target(target: str, force_report: bool) -> tuple[str, bool]:
    """Return (content, is_report)."""
    if target == "-":
        return sys.stdin.read(), True
    path = Path(target)
    if path.is_file():
        return path.read_text(errors="replace"), True
    if force_report and re.match(r"https?://", target):
        print(f"Fetching report from {target} ...", file=sys.stderr)
        return _fetch_report(target), True
    if force_report or iocs.classify(target) is None:
        return target, True
    return target, False


def _progress(quiet: bool):
    def emit(kind: str, data: dict) -> None:
        if quiet:
            return
        if kind == "tool":
            inp = data["input"]
            if data["name"] == "enrich_iocs":
                desc = ", ".join(iocs.defang(i["value"]) for i in inp.get("indicators", []))
            elif data["name"] == "extract_iocs":
                desc = f"{len(inp.get('text', ''))} chars"
            else:
                desc = json.dumps(inp)[:120]
            print(f"  -> {data['name']}: {desc}", file=sys.stderr)
        elif kind == "web_search":
            print(f"  -> web_search: {data['input'].get('query', '')}", file=sys.stderr)
        elif kind == "fallback":
            print(f"  (request declined by the primary model; continuing on {data['to']})", file=sys.stderr)
        elif kind == "text":
            print(f"  {data['text'].strip()[:300]}", file=sys.stderr)
        elif kind == "report":
            print("  -> writing report", file=sys.stderr)
    return emit


def cmd_investigate(args: argparse.Namespace) -> int:
    import anthropic

    from .agent import AgentError, CTIAgent
    from .report import render_markdown

    if not (os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_AUTH_TOKEN") or os.getenv("ANTHROPIC_PROFILE")):
        print("note: ANTHROPIC_API_KEY is not set; relying on an `ant auth login` profile if one exists.", file=sys.stderr)

    content, is_report = _resolve_target(args.target, args.report)
    if not content.strip():
        print("error: nothing to investigate", file=sys.stderr)
        return 2
    print(f"Investigating {'threat report' if is_report else 'indicator'} ...", file=sys.stderr)

    agent = CTIAgent(
        model=args.model, effort=args.effort, web_search=not args.no_web_search,
        fallbacks=not args.no_fallback, on_event=_progress(args.quiet),
    )
    try:
        result = agent.investigate(content, is_report=is_report)
    except AgentError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except anthropic.AuthenticationError:
        print("error: Claude API authentication failed. Set ANTHROPIC_API_KEY (or run `ant auth login`).", file=sys.stderr)
        return 1
    except anthropic.APIStatusError as e:
        print(f"error: Claude API returned {e.status_code}: {e.message}", file=sys.stderr)
        return 1
    except anthropic.APIConnectionError as e:
        print(f"error: could not reach the Claude API: {e}", file=sys.stderr)
        return 1

    meta = {"generated_at": result.generated_at, "model": result.model, "usage": result.stats.to_dict()}
    markdown = render_markdown(result.report, meta)
    doc = {"report": result.report, "meta": meta}

    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9]+", "-", result.report["title"].lower()).strip("-")[:60] or "report"
        (out / f"{slug}.md").write_text(markdown)
        (out / f"{slug}.json").write_text(json.dumps(doc, indent=2))
        print(f"Saved {out / (slug + '.md')} and {out / (slug + '.json')}", file=sys.stderr)
    print(json.dumps(doc, indent=2) if args.format == "json" else markdown)
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.source == "-" else (
        Path(args.source).read_text(errors="replace") if Path(args.source).is_file() else args.source
    )
    result = iocs.extract(text, include_private=args.include_private)
    if args.defang:
        result.iocs = {k: [iocs.defang(v) for v in vs] for k, vs in result.iocs.items()}
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    out = []
    for value in args.iocs:
        value = iocs.refang(value)
        kind = iocs.classify(value)
        if kind is None:
            out.append({"indicator": value, "error": "unrecognised indicator type"})
            continue
        out.append(enrichment.enrich(value, kind, args.sources))
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_sources(args: argparse.Namespace) -> int:
    for name, status in enrichment.source_status().items():
        print(f"{name:18} {status}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    p = argparse.ArgumentParser(prog="cti-agent", description="Automated cyber threat intelligence investigations.")
    sub = p.add_subparsers(dest="command", required=True)

    inv = sub.add_parser("investigate", help="Run a full investigation with Claude.")
    inv.add_argument("target", help="An IOC, a path to a report file, '-' for stdin, or a report URL with --report.")
    inv.add_argument("--report", action="store_true", help="Treat the target as a threat report (fetches URLs).")
    inv.add_argument("--out", help="Directory to save the Markdown and JSON report.")
    inv.add_argument("--format", choices=["md", "json"], default="md", help="What to print to stdout.")
    inv.add_argument("--model", help="Claude model (default claude-opus-5-5 or $CTI_AGENT_MODEL).")
    inv.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], help="Reasoning effort (default high).")
    inv.add_argument("--no-web-search", action="store_true", help="Disable Claude's web search tool.")
    inv.add_argument("--no-fallback", action="store_true", help="Disable server-side refusal fallbacks.")
    inv.add_argument("-q", "--quiet", action="store_true", help="Hide progress output.")
    inv.set_defaults(func=cmd_investigate)

    ext = sub.add_parser("extract", help="Extract IOCs from text without calling Claude.")
    ext.add_argument("source", help="Text, a file path, or '-' for stdin.")
    ext.add_argument("--defang", action="store_true", help="Print indicators defanged.")
    ext.add_argument("--include-private", action="store_true", help="Keep private/reserved IPs.")
    ext.set_defaults(func=cmd_extract)

    enr = sub.add_parser("enrich", help="Query the intel sources for IOCs without calling Claude.")
    enr.add_argument("iocs", nargs="+")
    enr.add_argument("--sources", nargs="*", choices=sorted(enrichment.SOURCES_BY_NAME), help="Limit to these sources.")
    enr.set_defaults(func=cmd_enrich)

    src = sub.add_parser("sources", help="Show which enrichment sources are configured.")
    src.set_defaults(func=cmd_sources)

    args = p.parse_args(argv)
    return args.func(args)
