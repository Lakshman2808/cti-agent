"""Tool definitions the agent can call, and the dispatcher that runs them."""

from __future__ import annotations

import json
from typing import Any

from . import enrichment, iocs
from .report import REPORT_SCHEMA

MAX_RESULT_CHARS = 12_000
MAX_BATCH = 15

_IOC_TYPE_ENUM = [t for t in iocs.IOC_TYPES if t != "attack_technique"]

CLIENT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "extract_iocs",
        "description": (
            "Extract and de-duplicate indicators of compromise from free text: IPs, domains, URLs, "
            "emails, file hashes, CVE IDs and MITRE ATT&CK technique IDs. Handles defanged notation "
            "(hxxp, [.], [at]). Private/reserved IPs are dropped. Use this on any new block of text, "
            "for example a report excerpt or text returned by a search."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"text": {"type": "string", "description": "Text to scan."}},
            "required": ["text"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "enrich_iocs",
        "description": (
            "Look up one or more indicators in every configured threat-intel source (VirusTotal, "
            "AbuseIPDB, AlienVault OTX, abuse.ch ThreatFox/URLhaus/MalwareBazaar, Shodan InternetDB, "
            "RDAP/WHOIS, DNS over HTTPS, NVD, CISA KEV). Sources are queried in parallel; each result "
            "has status ok, skipped (no API key) or error. These are passive lookups against intel "
            f"services and never contact the indicator itself. Up to {MAX_BATCH} indicators per call; "
            "batch related indicators together."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicators": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                            "type": {"type": "string", "enum": _IOC_TYPE_ENUM},
                        },
                        "required": ["value", "type"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["indicators"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "dns_lookup",
        "description": (
            "Resolve a specific DNS record for a domain via DNS over HTTPS. Use it to pivot, e.g. "
            "find the IPs a domain resolves to, or its MX/NS/TXT/CNAME records."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "record_type": {"type": "string", "enum": ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR"]},
            },
            "required": ["name", "record_type"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "submit_report",
        "description": (
            "Submit the final investigation report. Call this exactly once, when the investigation "
            "is complete. Every verdict must be backed by evidence from tool results or the source "
            "material; list anything you could not verify under gaps."
        ),
        "input_schema": REPORT_SCHEMA,
        "strict": True,
    },
]

WEB_SEARCH_TOOL = {"type": "web_search_20260209", "name": "web_search", "max_uses": 8}


def build_tools(web_search: bool) -> list[dict[str, Any]]:
    return CLIENT_TOOLS + ([WEB_SEARCH_TOOL] if web_search else [])


def _truncate(payload: Any) -> str:
    text = json.dumps(payload, ensure_ascii=False, default=str)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + '... [truncated]'
    return text


def run_tool(name: str, args: dict[str, Any]) -> tuple[str, bool]:
    """Execute a client tool. Returns (content, is_error)."""
    if name == "extract_iocs":
        return _truncate(iocs.extract(args["text"]).to_dict()), False

    if name == "enrich_iocs":
        items = args["indicators"][:MAX_BATCH]
        results = []
        for item in items:
            value = iocs.refang(item["value"].strip())
            kind = item["type"]
            if kind in ("md5", "sha1", "sha256", "sha512", "domain", "email"):
                value = value.lower()
            if kind == "cve":
                value = value.upper()
            results.append(enrichment.enrich(value, kind))
        payload: dict[str, Any] = {"results": results}
        if len(args["indicators"]) > MAX_BATCH:
            payload["note"] = f"only the first {MAX_BATCH} indicators were enriched; call again for the rest"
        return _truncate(payload), False

    if name == "dns_lookup":
        try:
            answers = enrichment.dns_query(args["name"], args["record_type"])
        except Exception as e:  # network errors are reported to the model, not raised
            return f"DNS lookup failed: {e}", True
        return _truncate({"name": args["name"], "type": args["record_type"], "answers": answers}), False

    return f"Unknown tool: {name}", True
