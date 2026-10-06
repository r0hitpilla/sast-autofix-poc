import os
import textwrap

import pytest

from config import load_config


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(textwrap.dedent("""\
        ollama:
          host: http://localhost:11434
          model: test-model
        laya:
          model: convaiinnovations/laya
        thresholds:
          fix: 0.8
          review: 0.4
        semgrep:
          rulesets:
            - p/security-audit
            - p/owasp-top-ten
        max_fix_retries: 2
        """))
    return str(path)


def test_load_config_reads_all_fields(config_file):
    cfg = load_config(config_file)
    assert cfg.ollama_host == "http://localhost:11434"
    assert cfg.ollama_model == "test-model"
    assert cfg.laya_model == "convaiinnovations/laya"
    assert cfg.threshold_fix == 0.8
    assert cfg.threshold_review == 0.4
    assert cfg.semgrep_rulesets == ["p/security-audit", "p/owasp-top-ten"]
    assert cfg.max_fix_retries == 2


def test_load_config_env_overrides_ollama_host(config_file, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://10.0.0.5:11434")
    cfg = load_config(config_file)
    assert cfg.ollama_host == "http://10.0.0.5:11434"
