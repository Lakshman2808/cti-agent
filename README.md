# CTI Agent

An autonomous cyber threat intelligence analyst built on the Claude API. Give it a
single indicator (IP, domain, URL, hash, email, CVE) or a whole threat report, and it
extracts the indicators, enriches them across threat-intel sources, pivots on what it
finds, maps behaviour to MITRE ATT&CK, and writes a structured report with verdicts,
evidence, recommended actions and detection ideas.

## Quick start

```bash
pip install -e .            # Python 3.10+
cp .env.example .env        # add ANTHROPIC_API_KEY; every other key is optional

cti-agent investigate 185.220.101[.]1
cti-agent investigate samples/sample_report.txt --out reports/
cti-agent investigate https://vendor.example/blog/apt-writeup --report
cat alert.txt | cti-agent investigate -
```

Progress (tool calls, searches) goes to stderr; the Markdown report goes to stdout.
`--out DIR` also saves `<title>.md` and `<title>.json`. `--format json` prints JSON instead.

### Without Claude

```bash
cti-agent extract samples/sample_report.txt --defang   # IOC extraction only
cti-agent enrich 8.8.8.8 evil[.]com CVE-2021-44228      # raw enrichment, no LLM
cti-agent sources                                      # which sources are configured
```

## How it works

1. **Input.** A target that is a file, `-`, or free text becomes a *report*; a lone
   recognisable indicator becomes an *IOC investigation*. URLs are treated as IOCs
   unless you pass `--report`, in which case the page is fetched and stripped to text.
2. **Extraction** (`cti_agent/iocs.py`). Regex extraction with refanging
   (`hxxp`, `[.]`, `[at]`, ...), de-duplication, hash-length disambiguation, private IP
   filtering and file-name false-positive suppression. For reports the extracted set is
   handed to the model up front.
3. **Agent loop** (`cti_agent/agent.py`). A manual tool-use loop on `claude-opus-5-5`
   with adaptive thinking, `effort: high`, streaming and prompt caching. Tools:
   - `extract_iocs` – run extraction on any new text
   - `enrich_iocs` – batch lookups across every applicable source, in parallel
   - `dns_lookup` – targeted DNS-over-HTTPS pivots
   - `web_search` – Claude's server-side search for vendor reporting and attribution
     (disable with `--no-web-search`)
   - `submit_report` – strict-schema tool the agent calls once to finish
4. **Report** (`cti_agent/report.py`). The JSON schema enforces verdict, confidence,
   severity, per-indicator evidence and sources, actors, malware, ATT&CK techniques,
   CVEs, relationships, actions, detections and gaps. Markdown output is defanged.

## Enrichment sources

| Source | Covers | Key |
|---|---|---|
| VirusTotal v3 | IP, domain, URL, hash | `VT_API_KEY` (required) |
| AbuseIPDB | IP | `ABUSEIPDB_API_KEY` (required) |
| AlienVault OTX | IP, domain, URL, hash, CVE | `OTX_API_KEY` (optional) |
| abuse.ch ThreatFox / URLhaus / MalwareBazaar | IP, domain, URL, hash | `ABUSECH_AUTH_KEY` (required, free) |
| Shodan InternetDB | IPv4 open ports, CPEs, vulns | none |
| RDAP (WHOIS) | IP, domain | none |
| DNS over HTTPS (dns.google) | domain | none |
| NVD | CVE | `NVD_API_KEY` (optional) |
| CISA KEV | CVE | none |

Sources without a key are skipped, the model is told which ones ran, and missing
coverage shows up under **Gaps** in the report. So the agent runs with only an
Anthropic key, and gets sharper as you add keys.

## Safety design

- **Passive only.** Every lookup goes to an intelligence service; nothing connects to
  the indicator itself (DNS goes over HTTPS to Google, not your resolver). The only
  direct fetch is a report URL you explicitly pass with `--report`.
- **Untrusted input.** Report text and tool results are wrapped and labelled as data;
  the system prompt tells the model to ignore embedded instructions and flag them.
  The sample report contains such an injection line to exercise this.
- **Refusal fallbacks.** Security content can trip safety classifiers. Requests use
  the server-side `fallbacks: "default"` option (beta `server-side-fallback-2026-07-01`),
  which re-runs a declined request on Anthropic's recommended fallback model. Turn it off
  with `--no-fallback`.
- **Bounded runs.** At most 40 model turns, 15 indicators per enrichment call, 12k chars
  per tool result, 8 web searches per turn.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | – | Claude API key (or an `ant auth login` profile) |
| `CTI_AGENT_MODEL` | `claude-opus-5-5` | Model; `--model` overrides |
| `CTI_AGENT_EFFORT` | `high` | `low`…`max`; lower is cheaper and faster |

## Using it as a library

```python
from cti_agent.agent import CTIAgent
from cti_agent.report import render_markdown

result = CTIAgent().investigate(open("report.txt").read(), is_report=True)
print(result.report["overall_verdict"], result.stats.to_dict())
print(render_markdown(result.report))
```

## Tests

```bash
pip install -e '.[dev]' && pytest
```

The tests cover extraction, source parsing via a mocked HTTP transport, and the agent
loop via a scripted fake Claude client, so they need no keys or network.

## Extending

Add a source by writing a `fn(value, kind) -> dict` in `cti_agent/enrichment.py` and
registering a `Source(...)` in `SOURCES`; it is picked up by `enrich_iocs`, the system
prompt and `cti-agent sources` automatically.
