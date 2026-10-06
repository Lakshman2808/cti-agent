"""The structured investigation report: JSON schema and Markdown rendering."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .iocs import defang

_VERDICT = {"type": "string", "enum": ["malicious", "suspicious", "benign", "unknown"]}
_CONFIDENCE = {"type": "string", "enum": ["high", "medium", "low"]}
_STR_LIST = {"type": "array", "items": {"type": "string"}}


def _obj(props: dict[str, Any]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


REPORT_SCHEMA = _obj({
    "title": {"type": "string", "description": "Short title for the investigation."},
    "executive_summary": {"type": "string", "description": "3-6 sentences: what this is, how bad, what to do."},
    "overall_verdict": _VERDICT,
    "confidence": _CONFIDENCE,
    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
    "indicators": {
        "type": "array",
        "items": _obj({
            "value": {"type": "string"},
            "type": {"type": "string"},
            "verdict": _VERDICT,
            "confidence": _CONFIDENCE,
            "evidence": {"type": "string", "description": "Concrete findings, citing the source for each."},
            "sources": _STR_LIST,
        }),
    },
    "threat_actors": _STR_LIST,
    "malware_families": _STR_LIST,
    "attack_techniques": {
        "type": "array",
        "items": _obj({
            "id": {"type": "string", "description": "MITRE ATT&CK ID, e.g. T1566.001"},
            "name": {"type": "string"},
            "evidence": {"type": "string"},
        }),
    },
    "vulnerabilities": {
        "type": "array",
        "items": _obj({
            "cve": {"type": "string"},
            "summary": {"type": "string"},
            "cvss": {"type": "string"},
            "known_exploited": {"type": "boolean"},
        }),
    },
    "relationships": {
        "type": "array",
        "description": "Pivots discovered, e.g. domain resolves_to IP, hash downloaded_from URL.",
        "items": _obj({"source": {"type": "string"}, "relation": {"type": "string"}, "target": {"type": "string"}}),
    },
    "recommended_actions": _STR_LIST,
    "detection_opportunities": {
        "type": "array",
        "items": {"type": "string"},
        "description": "Hunting queries, blocklist entries, or Sigma/YARA ideas.",
    },
    "gaps": {
        "type": "array",
        "items": {"type": "string"},
        "description": "What could not be checked (skipped sources, errors, missing context).",
    },
})


def render_markdown(report: dict[str, Any], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    out: list[str] = [f"# {report['title']}", ""]
    generated = meta.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out.append(
        f"**Verdict:** {report['overall_verdict'].upper()} · **Severity:** {report['severity']} · "
        f"**Confidence:** {report['confidence']}  "
    )
    out.append(f"_Generated {generated}" + (f" by {meta['model']}" if meta.get("model") else "") + "_")
    out += ["", "## Executive summary", "", report["executive_summary"], ""]

    if report["indicators"]:
        out += ["## Indicators", "", "| Indicator | Type | Verdict | Confidence | Evidence |", "|---|---|---|---|---|"]
        order = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}
        for i in sorted(report["indicators"], key=lambda x: order.get(x["verdict"], 9)):
            evidence = i["evidence"].replace("|", "\\|").replace("\n", " ")
            srcs = f" _({', '.join(i['sources'])})_" if i["sources"] else ""
            out.append(f"| `{defang(i['value'])}` | {i['type']} | {i['verdict']} | {i['confidence']} | {evidence}{srcs} |")
        out.append("")

    if report["threat_actors"] or report["malware_families"]:
        out += ["## Attribution", ""]
        if report["threat_actors"]:
            out.append(f"- **Threat actors:** {', '.join(report['threat_actors'])}")
        if report["malware_families"]:
            out.append(f"- **Malware families:** {', '.join(report['malware_families'])}")
        out.append("")

    if report["attack_techniques"]:
        out += ["## MITRE ATT&CK", "", "| ID | Technique | Evidence |", "|---|---|---|"]
        for t in report["attack_techniques"]:
            out.append(f"| {t['id']} | {t['name']} | {t['evidence'].replace('|', '/')} |")
        out.append("")

    if report["vulnerabilities"]:
        out += ["## Vulnerabilities", "", "| CVE | CVSS | Known exploited | Summary |", "|---|---|---|---|"]
        for v in report["vulnerabilities"]:
            out.append(f"| {v['cve']} | {v['cvss']} | {'yes (CISA KEV)' if v['known_exploited'] else 'no'} | {v['summary'].replace('|', '/')} |")
        out.append("")

    if report["relationships"]:
        out += ["## Relationships", ""]
        out += [f"- `{defang(r['source'])}` **{r['relation']}** `{defang(r['target'])}`" for r in report["relationships"]]
        out.append("")

    for key, heading in (
        ("recommended_actions", "Recommended actions"),
        ("detection_opportunities", "Detection opportunities"),
        ("gaps", "Gaps and limitations"),
    ):
        if report[key]:
            out += [f"## {heading}", ""] + [f"- {x}" for x in report[key]] + [""]

    if meta.get("usage"):
        u = meta["usage"]
        out += ["---", f"_Agent run: {u.get('turns', 0)} model turns, {u.get('tool_calls', 0)} tool calls, "
                f"{u.get('input_tokens', 0):,} input / {u.get('output_tokens', 0):,} output tokens._", ""]
    return "\n".join(out)
