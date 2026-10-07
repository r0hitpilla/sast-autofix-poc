import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import observability
from llm_usage import Call, UsageLedger
from observability import LangfuseTracer, NullTracer, from_config, is_cloud, read_key_file

KEYS = {"LANGFUSE_PUBLIC_KEY": "pk-lf-test", "LANGFUSE_SECRET_KEY": "sk-lf-test"}


def cfg(**kw):
    base = dict(langfuse_enabled=True, langfuse_host="http://127.0.0.1:3000",
                langfuse_allow_cloud=False, langfuse_capture_content=True)
    base.update(kw)
    return SimpleNamespace(**base)


NO_FILE = "/nonexistent/langfuse.env"


@pytest.mark.parametrize("host,cloud", [
    ("https://cloud.langfuse.com", True), ("https://us.cloud.langfuse.com", True),
    ("https://langfuse.com", True), ("http://127.0.0.1:3000", False),
    ("https://langfuse.internal.acme.io", False), ("https://notlangfuse.com", False),
])
def test_cloud_hosts_are_recognised(host, cloud):
    assert is_cloud(host) is cloud


def test_tracing_is_off_unless_switched_on():
    assert isinstance(from_config(cfg(langfuse_enabled=False), env=KEYS, key_file=NO_FILE), NullTracer)
    assert isinstance(from_config(SimpleNamespace(), env=KEYS, key_file=NO_FILE), NullTracer)


def test_tracing_is_off_without_keys():
    assert isinstance(from_config(cfg(), env={}, key_file=NO_FILE), NullTracer)


def test_a_cloud_host_is_refused_because_prompts_contain_source_code(capsys):
    t = from_config(cfg(langfuse_host="https://cloud.langfuse.com"), env=KEYS, key_file=NO_FILE)
    assert isinstance(t, NullTracer)
    assert "source code" in capsys.readouterr().err


def test_a_cloud_host_needs_an_explicit_opt_in():
    with patch.object(observability, "server_reachable", return_value=True), \
         patch.object(observability, "LangfuseTracer") as tracer:
        from_config(cfg(langfuse_host="https://cloud.langfuse.com", langfuse_allow_cloud=True),
                    env=KEYS, key_file=NO_FILE)
    tracer.assert_called_once()


def test_an_unreachable_server_turns_tracing_off_instead_of_slowing_the_scan():
    with patch.object(observability, "server_reachable", return_value=False):
        assert isinstance(from_config(cfg(), env=KEYS, key_file=NO_FILE), NullTracer)


def test_host_and_keys_come_from_the_environment_and_capture_setting_is_passed_on():
    env = {**KEYS, "LANGFUSE_HOST": "http://langfuse.lan:3000"}
    with patch.object(observability, "server_reachable", return_value=True), \
         patch.object(observability, "LangfuseTracer") as tracer:
        from_config(cfg(langfuse_capture_content=False), env=env, key_file=NO_FILE)
    assert tracer.call_args.args[:3] == ("http://langfuse.lan:3000", "pk-lf-test", "sk-lf-test")
    assert tracer.call_args.kwargs["capture_content"] is False


def test_any_startup_error_means_no_tracing_not_a_failed_run():
    with patch.object(observability, "server_reachable", return_value=True), \
         patch.object(observability, "LangfuseTracer", side_effect=RuntimeError("boom")):
        assert isinstance(from_config(cfg(), env=KEYS, key_file=NO_FILE), NullTracer)


def test_key_file_is_read_only_when_private(tmp_path):
    path = tmp_path / "langfuse.env"
    path.write_text('# keys\nLANGFUSE_PUBLIC_KEY="pk-lf-1"\nLANGFUSE_SECRET_KEY=sk-lf-1\n')
    os.chmod(path, 0o644)
    assert read_key_file(str(path)) == {}          # readable by others: refused
    os.chmod(path, 0o600)
    assert read_key_file(str(path)) == {"LANGFUSE_PUBLIC_KEY": "pk-lf-1", "LANGFUSE_SECRET_KEY": "sk-lf-1"}
    assert read_key_file(str(tmp_path / "missing.env")) == {}


def test_keys_from_the_private_file_are_used_when_the_environment_has_none(tmp_path):
    path = tmp_path / "langfuse.env"
    path.write_text("LANGFUSE_PUBLIC_KEY=pk-file\nLANGFUSE_SECRET_KEY=sk-file\n")
    os.chmod(path, 0o600)
    with patch.object(observability, "server_reachable", return_value=True), \
         patch.object(observability, "LangfuseTracer") as tracer:
        from_config(cfg(), env={}, key_file=str(path))
    assert tracer.call_args.args[1:3] == ("pk-file", "sk-file")


# ---- what is sent -----------------------------------------------------------

def tracer_with_memory(capture=True):
    exporter = InMemorySpanExporter()
    return LangfuseTracer("http://x", "pk", "sk", capture_content=capture, exporter=exporter,
                          processor="simple"), exporter


def attrs_of(exporter, name):
    return next(dict(s.attributes) for s in exporter.get_finished_spans() if s.name == name)


def test_a_call_becomes_a_generation_with_model_tokens_and_text():
    t, exp = tracer_with_memory()
    with t.run(name="run", session_id="42", tags=["ci"], metadata={"repository": "o/r"}):
        t.generation(name="fix", model="qwen", start_ns=1, end_ns=2, prompt_tokens=100, completion_tokens=40,
                     input="the prompt", output="the reply", metadata={"purpose": "fix", "ref": "a.py:1"})
    a = attrs_of(exp, "fix")
    assert a["langfuse.observation.type"] == "generation" and a["gen_ai.request.model"] == "qwen"
    assert json.loads(a["langfuse.observation.usage_details"]) == {"input": 100, "output": 40, "total": 140}
    assert a["langfuse.observation.input"] == "the prompt" and a["langfuse.observation.output"] == "the reply"
    assert a["langfuse.observation.metadata.ref"] == "a.py:1"
    root = attrs_of(exp, "run")
    assert root["langfuse.session.id"] == "42" and list(root["langfuse.trace.tags"]) == ["ci"]


def test_calls_are_children_of_the_run():
    t, exp = tracer_with_memory()
    with t.run(name="run"):
        t.generation(name="fix", model="m", start_ns=1, end_ns=2)
    spans = {s.name: s for s in exp.get_finished_spans()}
    assert spans["fix"].parent.span_id == spans["run"].context.span_id
    assert spans["fix"].context.trace_id == spans["run"].context.trace_id


def test_metadata_only_mode_never_sends_prompts_or_replies():
    t, exp = tracer_with_memory(capture=False)
    with t.run(name="run"):
        t.generation(name="fix", model="m", start_ns=1, end_ns=2, prompt_tokens=5, completion_tokens=2,
                     input="SECRET SOURCE CODE", output="more code")
    a = attrs_of(exp, "fix")
    assert "langfuse.observation.input" not in a and "langfuse.observation.output" not in a
    assert "SECRET" not in json.dumps({k: str(v) for k, v in a.items()})
    assert a["gen_ai.usage.input_tokens"] == 5       # usage is still sent


def test_a_failed_call_is_marked_as_an_error():
    t, exp = tracer_with_memory()
    with t.run(name="run"):
        t.generation(name="fix", model="m", start_ns=1, end_ns=2, ok=False, error="reply hit the limit")
    a = attrs_of(exp, "fix")
    assert a["langfuse.observation.level"] == "ERROR" and "limit" in a["langfuse.observation.status_message"]


def test_laya_calls_are_spans_without_tokens():
    t, exp = tracer_with_memory()
    with t.run(name="run"):
        t.span(name="laya_triage", start_ns=1, end_ns=2, metadata={"model": "laya"})
    a = attrs_of(exp, "laya_triage")
    assert a["langfuse.observation.type"] == "span" and "gen_ai.usage.input_tokens" not in a


def test_an_exporter_failure_never_reaches_the_scan():
    t, exp = tracer_with_memory()
    t._tracer = SimpleNamespace(start_span=lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    t.generation(name="fix", model="m", start_ns=1, end_ns=2)   # must not raise
    t.flush()


def test_the_null_tracer_accepts_everything_and_does_nothing():
    n = NullTracer()
    with n.run(name="x", session_id="1"):
        n.generation(name="a", model="m", start_ns=1, end_ns=2)
        n.span(name="b", start_ns=1, end_ns=2)
    n.flush(); n.shutdown()


# ---- the usage summary ------------------------------------------------------

def test_the_ledger_totals_by_purpose_and_model_and_reports_missing_counts():
    ledger = UsageLedger()
    mk = lambda **kw: Call(at="t", purpose="fix", model="qwen", provider="ollama", prompt_tokens=100,  # noqa: E731
                           completion_tokens=50, duration_ms=2000, ok=True, **kw)
    ledger.record(mk())
    ledger.record(mk(ref="a.py:1"))
    ledger.record(Call(at="t", purpose="laya_triage", model="laya", provider="laya", prompt_tokens=None,
                       completion_tokens=None, duration_ms=300, ok=False, error="gpu"))
    s = ledger.summary()
    assert (s["calls"], s["errors"], s["prompt_tokens"], s["completion_tokens"], s["total_tokens"]) == (3, 1, 200, 100, 300)
    assert s["calls_with_token_counts"] == 2
    assert s["by_purpose"]["fix"]["calls"] == 2 and s["by_model"]["laya"]["errors"] == 1
    assert ledger.report()["calls"][0]["model"] == "qwen"


def test_the_run_report_carries_the_usage_and_a_readable_summary():
    from report import RunReport, to_json, to_markdown
    ledger = UsageLedger()
    ledger.record(Call(at="t", purpose="triage", model="qwen", provider="ollama", prompt_tokens=1200,
                       completion_tokens=300, duration_ms=5000, ok=True))
    rr = RunReport(target="o/r @ main")
    rr.usage = ledger
    data = json.loads(to_json(rr))
    assert data["llm_usage"]["summary"]["total_tokens"] == 1500
    md = to_markdown(rr)
    assert "## AI usage" in md and "1,500 tokens" in md and "| triage | 1 | 1,200 | 300 |" in md
    assert json.loads(to_json(RunReport(target="x")))["llm_usage"] is None
