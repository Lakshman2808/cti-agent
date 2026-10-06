"""Drive the agent loop with a scripted fake Claude client (no network, no key)."""

from types import SimpleNamespace as NS

from cti_agent import agent as agent_mod
from cti_agent.agent import CTIAgent
from cti_agent.report import render_markdown

REPORT = {
    "title": "Investigation of 45.9.148.10",
    "executive_summary": "C2 server.",
    "overall_verdict": "malicious", "confidence": "medium", "severity": "high",
    "indicators": [{"value": "45.9.148.10", "type": "ipv4", "verdict": "malicious", "confidence": "medium",
                    "evidence": "Seen in OTX pulses | tagged C2", "sources": ["otx"]}],
    "threat_actors": [], "malware_families": ["AsyncRAT"],
    "attack_techniques": [{"id": "T1071.001", "name": "Web Protocols", "evidence": "HTTPS beacons"}],
    "vulnerabilities": [], "relationships": [{"source": "evil.com", "relation": "resolves_to", "target": "45.9.148.10"}],
    "recommended_actions": ["Block the IP"], "detection_opportunities": ["Proxy logs for 45.9.148.10"],
    "gaps": ["VirusTotal skipped"],
}


def _resp(stop, *blocks):
    return NS(stop_reason=stop, content=list(blocks), model="claude-opus-5-5",
              usage=NS(input_tokens=100, output_tokens=50, cache_read_input_tokens=0, cache_creation_input_tokens=0))


class FakeClient:
    def __init__(self, script):
        self.script, self.calls = list(script), []
        self.beta = NS(messages=NS(stream=self._stream))

    def _stream(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})
        resp = self.script.pop(0)

        class Ctx:
            def __enter__(s): return NS(get_final_message=lambda: resp)
            def __exit__(s, *a): return False
        return Ctx()


def test_loop_runs_tools_then_returns_report(monkeypatch):
    seen = []
    monkeypatch.setattr(agent_mod, "run_tool", lambda name, args: (seen.append((name, args)) or ('{"ok": true}', False)))
    client = FakeClient([
        _resp("tool_use",
              NS(type="text", text="Enriching."),
              NS(type="tool_use", id="t1", name="enrich_iocs", input={"indicators": [{"value": "45.9.148.10", "type": "ipv4"}]}),
              NS(type="tool_use", id="t2", name="dns_lookup", input={"name": "evil.com", "record_type": "A"})),
        _resp("tool_use", NS(type="tool_use", id="t3", name="submit_report", input=REPORT)),
    ])
    result = CTIAgent(client, web_search=False).investigate("45.9.148[.]10", is_report=False)

    assert result.report["overall_verdict"] == "malicious"
    assert [n for n, _ in seen] == ["enrich_iocs", "dns_lookup"]
    assert result.stats.turns == 2 and result.stats.tool_calls == 2
    # both tool results go back in one user message
    second = client.calls[1]["messages"]
    assert [b["tool_use_id"] for b in second[-1]["content"]] == ["t1", "t2"]
    # request shape
    kw = client.calls[0]
    assert kw["model"] == "claude-opus-5-5" and kw["thinking"] == {"type": "adaptive"}
    assert kw["fallbacks"] == "default" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert "Refanged value for tool calls: 45.9.148.10" in kw["messages"][0]["content"]


def test_nudges_when_model_stops_without_report():
    client = FakeClient([
        _resp("end_turn", NS(type="text", text="Looks bad.")),
        _resp("tool_use", NS(type="tool_use", id="t1", name="submit_report", input=REPORT)),
    ])
    result = CTIAgent(client, web_search=False, fallbacks=False).investigate("report text", is_report=True)
    assert result.report["title"].startswith("Investigation")
    assert "fallbacks" not in client.calls[0]
    assert client.calls[1]["messages"][-1]["content"].startswith("Finish the investigation")


def test_pause_turn_resumes_without_extra_user_message():
    client = FakeClient([
        _resp("pause_turn", NS(type="server_tool_use", id="s1", input={"query": "x"})),
        _resp("tool_use", NS(type="tool_use", id="t1", name="submit_report", input=REPORT)),
    ])
    CTIAgent(client).investigate("8.8.8.8", is_report=False)
    assert client.calls[1]["messages"][-1]["role"] == "assistant"


def test_fallback_echo_drops_declined_blocks():
    content = [NS(type="thinking"), NS(type="tool_use", id="a"), NS(type="text", text="partial"),
               NS(type="fallback", to=NS(model="claude-opus-4-8")), NS(type="tool_use", id="b")]
    cleaned = agent_mod._clean_for_echo(content)
    assert [b.type for b in cleaned] == ["text", "fallback", "tool_use"]


def test_markdown_render_defangs_and_escapes():
    md = render_markdown(REPORT, {"model": "claude-opus-5-5", "usage": {"turns": 2, "tool_calls": 3}})
    assert "`45[.]9[.]148[.]10`" in md and "OTX pulses \\| tagged" in md
    assert "## MITRE ATT&CK" in md and "`evil[.]com` **resolves_to**" in md


def test_tool_schemas_are_strict_compatible():
    from cti_agent.tools import CLIENT_TOOLS

    def check(schema):
        if schema.get("type") == "object":
            assert schema["additionalProperties"] is False
            assert set(schema["required"]) == set(schema["properties"])
            for sub in schema["properties"].values():
                check(sub)
        elif schema.get("type") == "array":
            check(schema["items"])
    for tool in CLIENT_TOOLS:
        check(tool["input_schema"])
