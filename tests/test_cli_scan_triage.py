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

    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "--target-repo", "."],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload == []
