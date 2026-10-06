"""Threat-intel enrichment sources.

Every source queries an intelligence service *about* an indicator. None of
them connects to the indicator itself, so investigating a C2 domain never
sends traffic to that domain.

Sources with no API key configured are reported as skipped, not as errors,
so the agent works out of the box with only the keyless sources.
"""

from __future__ import annotations

import base64
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from . import __version__

TIMEOUT = httpx.Timeout(20.0, connect=10.0)
USER_AGENT = f"cti-agent/{__version__}"

_client_lock = threading.Lock()
_client: httpx.Client | None = None


def http() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None:
            _client = httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}, follow_redirects=True)
        return _client


def _ts(epoch: int | None) -> str | None:
    if not epoch:
        return None
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


class Skipped(Exception):
    """Raised when a source cannot run (missing key, unsupported type)."""


@dataclass(frozen=True)
class Source:
    name: str
    types: frozenset[str]
    fn: Callable[[str, str], dict[str, Any]]
    key_env: str | None = None
    key_required: bool = True

    def available(self) -> bool:
        return not (self.key_env and self.key_required and not os.getenv(self.key_env))


# ---------------------------------------------------------------- VirusTotal

def _virustotal(value: str, kind: str) -> dict[str, Any]:
    key = os.environ["VT_API_KEY"]
    if kind in ("md5", "sha1", "sha256"):
        path = f"files/{value}"
    elif kind in ("ipv4", "ipv6"):
        path = f"ip_addresses/{value}"
    elif kind == "domain":
        path = f"domains/{value}"
    else:
        path = "urls/" + base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    r = http().get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key})
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    flagged = sorted(
        (eng for eng, res in a.get("last_analysis_results", {}).items() if res.get("category") == "malicious")
    )[:10]
    out = {
        "found": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": a.get("reputation"),
        "tags": a.get("tags", [])[:15],
        "flagged_by": flagged,
        "last_analysis": _ts(a.get("last_analysis_date")),
    }
    if kind in ("md5", "sha1", "sha256"):
        ptc = a.get("popular_threat_classification") or {}
        out |= {
            "names": a.get("names", [])[:10],
            "type": a.get("type_description"),
            "size": a.get("size"),
            "sha256": a.get("sha256"),
            "first_seen": _ts(a.get("first_submission_date")),
            "threat_label": ptc.get("suggested_threat_label"),
            "families": [f["value"] for f in ptc.get("popular_threat_name", [])][:5],
        }
    elif kind in ("ipv4", "ipv6"):
        out |= {"asn": a.get("asn"), "as_owner": a.get("as_owner"), "country": a.get("country"), "network": a.get("network")}
    elif kind == "domain":
        out |= {"registrar": a.get("registrar"), "created": _ts(a.get("creation_date")), "categories": a.get("categories")}
    return out


# ----------------------------------------------------------------- AbuseIPDB

def _abuseipdb(value: str, kind: str) -> dict[str, Any]:
    r = http().get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
        headers={"Key": os.environ["ABUSEIPDB_API_KEY"], "Accept": "application/json"},
    )
    r.raise_for_status()
    d = r.json()["data"]
    categories = sorted({c for rep in d.get("reports", [])[:50] for c in rep.get("categories", [])})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "last_reported": d.get("lastReportedAt"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "domain": d.get("domain"),
        "country": d.get("countryCode"),
        "is_tor": d.get("isTor"),
        "is_whitelisted": d.get("isWhitelisted"),
        "report_category_ids": categories,
    }


# ------------------------------------------------------------ AlienVault OTX

_OTX_SECTION = {
    "ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url",
    "md5": "file", "sha1": "file", "sha256": "file", "cve": "cve",
}


def _otx(value: str, kind: str) -> dict[str, Any]:
    headers = {"X-OTX-API-KEY": os.environ["OTX_API_KEY"]} if os.getenv("OTX_API_KEY") else {}
    r = http().get(f"https://otx.alienvault.com/api/v1/indicators/{_OTX_SECTION[kind]}/{value}/general", headers=headers)
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    d = r.json()
    pi = d.get("pulse_info", {}) or {}
    pulses = pi.get("pulses", [])
    related = pi.get("related", {}) or {}
    families, adversaries = set(), set()
    for group in related.values():
        families.update(group.get("malware_families", []) or [])
        adversaries.update(group.get("adversary", []) or [])
    for p in pulses:
        for fam in p.get("malware_families", []) or []:
            families.add(fam.get("display_name") if isinstance(fam, dict) else fam)
        if p.get("adversary"):
            adversaries.add(p["adversary"])
    return {
        "found": True,
        "pulse_count": pi.get("count", 0),
        "pulses": [
            {"name": p.get("name"), "created": (p.get("created") or "")[:10], "tags": p.get("tags", [])[:8]}
            for p in pulses[:8]
        ],
        "malware_families": sorted(f for f in families if f)[:15],
        "adversaries": sorted(a for a in adversaries if a)[:10],
        "attack_ids": sorted(
            {
                (t.get("id") if isinstance(t, dict) else t)
                for p in pulses for t in (p.get("attack_ids") or [])
            } - {None}
        )[:20],
        "reputation": d.get("reputation"),
        "country": d.get("country_name"),
        "asn": d.get("asn"),
    }


# ------------------------------------------------------------------ abuse.ch

def _abusech_headers() -> dict[str, str]:
    return {"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]}


def _threatfox(value: str, kind: str) -> dict[str, Any]:
    r = http().post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "search_ioc", "search_term": value, "exact_match": True},
        headers=_abusech_headers(),
    )
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") != "ok":
        return {"found": False, "status": d.get("query_status")}
    return {
        "found": True,
        "matches": [
            {
                "ioc": x.get("ioc"),
                "threat_type": x.get("threat_type_desc"),
                "malware": x.get("malware_printable"),
                "confidence": x.get("confidence_level"),
                "first_seen": x.get("first_seen"),
                "last_seen": x.get("last_seen"),
                "tags": x.get("tags"),
                "reference": x.get("reference"),
            }
            for x in d.get("data", [])[:10]
        ],
    }


def _urlhaus(value: str, kind: str) -> dict[str, Any]:
    if kind == "url":
        endpoint, data = "url/", {"url": value}
    elif kind in ("md5", "sha256"):
        endpoint, data = "payload/", {f"{kind}_hash": value}
    else:
        endpoint, data = "host/", {"host": value}
    r = http().post(f"https://urlhaus-api.abuse.ch/v1/{endpoint}", data=data, headers=_abusech_headers())
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") != "ok":
        return {"found": False, "status": d.get("query_status")}
    out: dict[str, Any] = {"found": True}
    if kind == "url":
        out |= {
            "url_status": d.get("url_status"),
            "threat": d.get("threat"),
            "date_added": d.get("date_added"),
            "tags": d.get("tags"),
            "payloads": [
                {"sha256": p.get("response_sha256"), "signature": p.get("signature"), "file_type": p.get("file_type")}
                for p in (d.get("payloads") or [])[:5]
            ],
        }
    elif endpoint == "payload/":
        out |= {
            "signature": d.get("signature"),
            "file_type": d.get("file_type"),
            "first_seen": d.get("firstseen"),
            "url_count": d.get("url_count"),
            "urls": [u.get("url") for u in (d.get("urls") or [])[:10]],
        }
    else:
        urls = d.get("urls") or []
        out |= {
            "url_count": d.get("url_count"),
            "first_seen": d.get("firstseen"),
            "blacklists": d.get("blacklists"),
            "urls": [{"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat"), "tags": u.get("tags")} for u in urls[:10]],
        }
    return out


def _malwarebazaar(value: str, kind: str) -> dict[str, Any]:
    r = http().post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": value}, headers=_abusech_headers())
    r.raise_for_status()
    d = r.json()
    if d.get("query_status") != "ok":
        return {"found": False, "status": d.get("query_status")}
    x = d["data"][0]
    intel = x.get("intelligence") or {}
    return {
        "found": True,
        "file_name": x.get("file_name"),
        "file_type": x.get("file_type"),
        "signature": x.get("signature"),
        "tags": x.get("tags"),
        "first_seen": x.get("first_seen"),
        "delivery_method": x.get("delivery_method"),
        "sha256": x.get("sha256_hash"),
        "imphash": x.get("imphash"),
        "ssdeep": x.get("ssdeep"),
        "clamav": intel.get("clamav"),
        "yara_rules": [y.get("rule_name") for y in (x.get("yara_rules") or [])][:10],
        "vendor_intel": sorted((x.get("vendor_intel") or {}).keys()),
    }


# ----------------------------------------------------------- keyless sources

def _shodan_internetdb(value: str, kind: str) -> dict[str, Any]:
    r = http().get(f"https://internetdb.shodan.io/{value}")
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    d = r.json()
    return {
        "found": True,
        "ports": d.get("ports"),
        "hostnames": d.get("hostnames", [])[:15],
        "tags": d.get("tags"),
        "cpes": d.get("cpes", [])[:15],
        "vulns": d.get("vulns", [])[:20],
    }


def _rdap(value: str, kind: str) -> dict[str, Any]:
    path = "domain" if kind == "domain" else "ip"
    r = http().get(f"https://rdap.org/{path}/{value}", headers={"Accept": "application/rdap+json"})
    if r.status_code == 404:
        return {"found": False}
    r.raise_for_status()
    d = r.json()
    events = {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in d.get("events", [])}
    entities = []
    for ent in d.get("entities", [])[:6]:
        name = None
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                name = item[3]
        entities.append({"roles": ent.get("roles"), "name": name or ent.get("handle")})
    out = {"found": True, "handle": d.get("handle"), "name": d.get("name"), "status": d.get("status"), "events": events, "entities": entities}
    if kind == "domain":
        out["nameservers"] = [ns.get("ldhName") for ns in d.get("nameservers", [])][:8]
    else:
        out |= {"range": f"{d.get('startAddress')} - {d.get('endAddress')}", "country": d.get("country"), "type": d.get("type")}
    return out


def _dns(value: str, kind: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        out[rtype] = dns_query(value, rtype)
    return out


def dns_query(name: str, rtype: str = "A") -> list[str]:
    """DNS over HTTPS via Google, so the query never leaves from the local resolver."""
    r = http().get("https://dns.google/resolve", params={"name": name, "type": rtype})
    r.raise_for_status()
    return [a.get("data") for a in r.json().get("Answer", []) or []][:20]


def _nvd(value: str, kind: str) -> dict[str, Any]:
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
    r = http().get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": value}, headers=headers)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return {"found": False}
    c = vulns[0]["cve"]
    desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), None)
    metrics = c.get("metrics", {})
    cvss = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            cvss = {"version": data.get("version"), "score": data.get("baseScore"), "severity": data.get("baseSeverity") or metrics[key][0].get("baseSeverity"), "vector": data.get("vectorString")}
            break
    return {
        "found": True,
        "published": (c.get("published") or "")[:10],
        "description": desc,
        "cvss": cvss,
        "cwe": sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])}),
        "references": [ref["url"] for ref in c.get("references", [])][:8],
    }


_kev_cache: dict[str, dict] | None = None
_kev_lock = threading.Lock()


def _cisa_kev(value: str, kind: str) -> dict[str, Any]:
    global _kev_cache
    with _kev_lock:
        if _kev_cache is None:
            r = http().get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
            r.raise_for_status()
            _kev_cache = {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}
    v = _kev_cache.get(value.upper())
    if not v:
        return {"in_kev": False}
    return {
        "in_kev": True,
        "vendor": v.get("vendorProject"),
        "product": v.get("product"),
        "name": v.get("vulnerabilityName"),
        "date_added": v.get("dateAdded"),
        "ransomware_use": v.get("knownRansomwareCampaignUse"),
        "required_action": v.get("requiredAction"),
    }


_IP = frozenset({"ipv4", "ipv6"})
_HASH = frozenset({"md5", "sha1", "sha256"})

SOURCES: list[Source] = [
    Source("virustotal", _IP | _HASH | {"domain", "url"}, _virustotal, "VT_API_KEY"),
    Source("abuseipdb", _IP, _abuseipdb, "ABUSEIPDB_API_KEY"),
    Source("otx", _IP | _HASH | {"domain", "url", "cve"}, _otx, "OTX_API_KEY", key_required=False),
    Source("threatfox", _IP | _HASH | {"domain", "url"}, _threatfox, "ABUSECH_AUTH_KEY"),
    Source("urlhaus", _IP | {"domain", "url", "md5", "sha256"}, _urlhaus, "ABUSECH_AUTH_KEY"),
    Source("malwarebazaar", _HASH, _malwarebazaar, "ABUSECH_AUTH_KEY"),
    Source("shodan_internetdb", frozenset({"ipv4"}), _shodan_internetdb),
    Source("rdap", _IP | {"domain"}, _rdap),
    Source("dns", frozenset({"domain"}), _dns),
    Source("nvd", frozenset({"cve"}), _nvd, "NVD_API_KEY", key_required=False),
    Source("cisa_kev", frozenset({"cve"}), _cisa_kev),
]
SOURCES_BY_NAME = {s.name: s for s in SOURCES}


def source_status() -> dict[str, str]:
    """Which sources will run, for the system prompt and `cti-agent sources`."""
    return {
        s.name: ("ready" if s.available() else f"skipped (set {s.key_env})") + f" - {', '.join(sorted(s.types))}"
        for s in SOURCES
    }


_cache: dict[tuple[str, str], dict] = {}
_cache_lock = threading.Lock()


def _run_one(source: Source, value: str, kind: str) -> dict[str, Any]:
    if not source.available():
        return {"status": "skipped", "reason": f"{source.key_env} not set"}
    key = (source.name, value)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    try:
        result = {"status": "ok", "data": source.fn(value, kind)}
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        hint = {401: "invalid API key", 403: "forbidden / invalid key", 429: "rate limited"}.get(code, "")
        result = {"status": "error", "error": f"HTTP {code} {hint}".strip()}
    except httpx.HTTPError as e:
        result = {"status": "error", "error": f"{type(e).__name__}: {e}"[:200]}
    except (KeyError, ValueError, TypeError, IndexError) as e:
        result = {"status": "error", "error": f"unexpected response shape: {e}"[:200]}
    if result["status"] == "ok":
        with _cache_lock:
            _cache[key] = result
    return result


def enrich(value: str, kind: str, sources: list[str] | None = None) -> dict[str, Any]:
    """Query every applicable source for one indicator, in parallel."""
    chosen = [s for s in SOURCES if kind in s.types and (not sources or s.name in sources)]
    if not chosen:
        return {"indicator": value, "type": kind, "results": {}, "note": f"no sources cover type '{kind}'"}
    with ThreadPoolExecutor(max_workers=len(chosen)) as pool:
        futures = {s.name: pool.submit(_run_one, s, value, kind) for s in chosen}
        results = {name: f.result() for name, f in futures.items()}
    return {"indicator": value, "type": kind, "results": results}
