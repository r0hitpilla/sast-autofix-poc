import json
import subprocess
import sys


def test_scan_subcommand_prints_json_findings(tmp_path, monkeypatch):
    # Uses a fake semgrep on PATH so this test needs no real scanner/services.
    fake_semgrep = tmp_path / "semgrep"
    fake_semgrep.write_text(
        "#!/bin/sh\n"
        'echo \'{"results": []}\'\n'
    )
    fake_semgrep.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{subprocess.os.environ['PATH']}")
    # Semgrep only: the real config also runs gitleaks and osv-scanner, which
    # would find real things in this repository.
    import yaml
    config = yaml.safe_load(open("config.yaml"))
    config["engines"] = ["semgrep"]
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))

    result = subprocess.run(
        [sys.executable, "cli.py", "--config", str(config_path), "scan", "--target-repo", "."],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == []
