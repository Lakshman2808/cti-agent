import httpx
import pytest

from cti_agent import enrichment


@pytest.fixture
def mock_http(monkeypatch):
    routes = {}

    def handler(request: httpx.Request) -> httpx.Response:
        for prefix, response in routes.items():
            if str(request.url).startswith(prefix):
                return response(request) if callable(response) else response
        return httpx.Response(404, json={})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(enrichment, "_client", client)
    enrichment._cache.clear()
    return routes


def test_keyed_sources_skip_without_key(monkeypatch, mock_http):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    out = enrichment.enrich("1.2.3.4", "ipv4", ["virustotal", "abuseipdb"])
    assert out["results"]["virustotal"]["status"] == "skipped"
    assert out["results"]["abuseipdb"]["status"] == "skipped"


def test_virustotal_summary(monkeypatch, mock_http):
    monkeypatch.setenv("VT_API_KEY", "x")
    mock_http["https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"] = httpx.Response(200, json={
        "data": {"attributes": {
            "last_analysis_stats": {"malicious": 7, "harmless": 50},
            "last_analysis_results": {"EngA": {"category": "malicious"}, "EngB": {"category": "harmless"}},
            "asn": 123, "as_owner": "BadHost", "country": "NL", "tags": [],
        }}
    })
    r = enrichment.enrich("1.2.3.4", "ipv4", ["virustotal"])["results"]["virustotal"]
    assert r["status"] == "ok"
    assert r["data"]["malicious"] == 7 and r["data"]["flagged_by"] == ["EngA"] and r["data"]["as_owner"] == "BadHost"


def test_http_errors_are_reported_not_raised(monkeypatch, mock_http):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "x")
    mock_http["https://api.abuseipdb.com"] = httpx.Response(429, json={})
    r = enrichment.enrich("1.2.3.4", "ipv4", ["abuseipdb"])["results"]["abuseipdb"]
    assert r == {"status": "error", "error": "HTTP 429 rate limited"}


def test_cisa_kev(mock_http):
    enrichment._kev_cache = None
    mock_http["https://www.cisa.gov"] = httpx.Response(200, json={"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j", "knownRansomwareCampaignUse": "Known"}
    ]})
    r = enrichment.enrich("CVE-2021-44228", "cve", ["cisa_kev"])["results"]["cisa_kev"]
    assert r["data"]["in_kev"] is True and r["data"]["ransomware_use"] == "Known"
    enrichment._kev_cache = None
