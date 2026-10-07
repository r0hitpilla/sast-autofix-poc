"""How good are the exploit tests? Measured on the demo-orders code.

For each vulnerability class the model writes an exploit test. A test is VALID
when it fails (by assertion) on the vulnerable code AND passes once a known-good
fix is applied. A test that fails on the vulnerable code but also fails on a
correct fix would wrongly condemn good fixes; one that passes on the
vulnerable code proves nothing. Only valid tests are worth having.

    # a clone of the demo-orders branch with its .venv ready:
    git clone -b demo-orders sample_vuln_app /tmp/x && python -m venv /tmp/x/.venv && \\
        /tmp/x/.venv/bin/pip install -r /tmp/x/requirements.txt pytest
    venv/bin/python -m benchmark.proof_run --target /tmp/x
    venv/bin/python -m benchmark.proof_run --target /tmp/x --classes xss path_traversal
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import proof  # noqa: E402
from code_context import numbered_context, numbered_header  # noqa: E402
from config import load_config  # noqa: E402
from ollama_client import OllamaClient  # noqa: E402
from scanner import scan  # noqa: E402

RESULTS = os.path.join(ROOT, "benchmark", "results")

IMPORTS = ("import os\nimport sqlite3\nimport subprocess\n", "import os\nimport re\nimport sqlite3\nimport subprocess\n")
FLASK_IMPORT = ("from flask import Blueprint, jsonify, render_template_string, request, send_file",
                "from flask import Blueprint, abort, jsonify, render_template_string, request, send_file, send_from_directory")

# class -> replacements in orders.py that a careful engineer would make
REFERENCE_FIXES = {
    "sql_injection": [(
        "    query = f\"SELECT id, customer, item, qty, status FROM orders WHERE customer = '{customer}'\"\n"
        "    rows = _db().execute(query).fetchall()",
        "    rows = _db().execute(\"SELECT id, customer, item, qty, status FROM orders WHERE customer = ?\", (customer,)).fetchall()")],
    "command_injection": [IMPORTS, FLASK_IMPORT, (
        "    archive = os.path.join(EXPORT_DIR, f\"{name}.tgz\")\n"
        "    subprocess.run(f\"tar -czf {archive} -C {INVOICE_DIR} .\", shell=True, check=True)",
        "    if not re.fullmatch(r\"[A-Za-z0-9_-]+\", name):\n        abort(400)\n"
        "    archive = os.path.join(EXPORT_DIR, f\"{name}.tgz\")\n"
        "    subprocess.run([\"tar\", \"-czf\", archive, \"-C\", INVOICE_DIR, \".\"], check=True)")],
    "unsafe_yaml": [("yaml.load(request.data, Loader=yaml.Loader)", "yaml.safe_load(request.data)")],
    "xss": [("render_template_string(f\"<h2>Receipt</h2><p>{note}</p>\")",
             "render_template_string(\"<h2>Receipt</h2><p>{{ note }}</p>\", note=note)")],
    "path_traversal": [FLASK_IMPORT, ("return send_file(os.path.join(INVOICE_DIR, name))",
                                      "return send_from_directory(INVOICE_DIR, name)")],
    "tls_verification": [("timeout=5, verify=False)", "timeout=5)")],
}


def git(target, *args):
    return subprocess.run(["git", *args], cwd=target, capture_output=True, text=True, check=True).stdout


def reset(target):
    git(target, "checkout", "-f", "demo-orders")
    git(target, "clean", "-fdq", "tests", "templates", "exports", "invoices")


def apply_reference_fix(target, key):
    path = os.path.join(target, "orders.py")
    text = open(path).read()
    for old, new in REFERENCE_FIXES[key]:
        assert old in text, f"reference fix for {key}: text not found: {old[:60]!r}"
        text = text.replace(old, new, 1)
    open(path, "w").write(text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m benchmark.proof_run")
    ap.add_argument("--target", required=True, help="a clone of demo-orders with a ready .venv")
    ap.add_argument("--classes", nargs="*", default=list(REFERENCE_FIXES))
    ap.add_argument("--attempts", type=int, default=3)
    args = ap.parse_args(argv)

    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    ollama = OllamaClient(host=cfg.ollama_host, model=cfg.ollama_model)
    target = os.path.abspath(args.target)
    rows = []
    for key in args.classes:
        reset(target)
        findings = [f for f in scan(target, cfg.semgrep_rulesets, ("semgrep",))
                    if (c := proof.classify(f)) and c.key == key]
        if not findings:
            rows.append({"class": key, "status": "no finding"})
            print(f"{key:20} no finding of this class in the code", flush=True)
            continue
        f = min(findings, key=lambda x: x.line)
        started = time.time()
        test, status, reason = proof.prepare(
            f, ollama, target, cfg.fix_models, context=numbered_context(target, f),
            header=numbered_header(target, f.file), attempts=args.attempts, timeout=60,
            rulesets=cfg.semgrep_rulesets, engines=("semgrep",))
        row = {"class": key, "finding": f"{f.file}:{f.line}", "prepare": status, "seconds": round(time.time() - started)}
        if test is not None:
            row["attempts"] = test.attempts
            row["model"] = test.model
            apply_reference_fix(target, key)
            outcome, output = proof.run_test(target, test.path, 60)
            row["on_reference_fix"] = outcome
            row["valid"] = outcome == "passed"
            if outcome != "passed":
                row["why_not"] = output[-500:]
            row["test"] = test.code
        else:
            row["reason"] = reason
        rows.append(row)
        verdict = ("VALID" if row.get("valid") else f"INVALID ({row.get('on_reference_fix')})") if test else status.upper()
        print(f"{key:20} {verdict:22} attempts={row.get('attempts', '-')} {row['seconds']}s  {row.get('reason', '')[:90]}", flush=True)
    reset(target)

    ran = [r for r in rows if r.get("prepare")]
    ready = [r for r in ran if r["prepare"] == "ready"]
    valid = [r for r in ready if r.get("valid")]
    summary = {"classes": len(ran), "ready": len(ready), "valid": len(valid),
               "false_refutations": sum(1 for r in ready if r.get("on_reference_fix") == "failed")}
    print(f"\nvalid proofs: {len(valid)}/{len(ran)} classes | tests that would wrongly condemn a correct fix: "
          f"{summary['false_refutations']}")
    os.makedirs(RESULTS, exist_ok=True)
    out = os.path.join(RESULTS, f"proof-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.json")
    with open(out, "w") as fh:
        json.dump({"summary": summary, "rows": rows, "models": cfg.fix_models}, fh, indent=2)
    print("saved", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
