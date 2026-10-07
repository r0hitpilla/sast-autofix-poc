"""Does Laya's fix trust score tell good fixes from bad ones?

Labelled changes: GOOD ones really remediate the problem; BAD ones look like
fixes (the scanner would go quiet, tests would pass) but leave the weakness or
break something. Each is scored with the SAME verified facts, so any
difference comes from Laya reading the change itself.

    venv/bin/python -m benchmark.fix_trust_run
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from config import load_config  # noqa: E402
from fix_trust import fix_trust  # noqa: E402
from laya_client import LayaClient  # noqa: E402
from models import Finding, ValidationResult  # noqa: E402


def case(label, name, cwe, message, file, removed, added, review="the change addresses the weakness"):
    diff = "".join(f"-{r}\n" for r in removed) + "".join(f"+{a}\n" for a in added)
    return label, name, Finding(file=file, line=1, rule_id="r", cwe=cwe, message=message, snippet=removed[0]), diff, review


CASES = [
    # ---- real remediations
    case("good", "sql parameterised", "CWE-89", "string-interpolated SQL query", "orders.py",
         ['query = f"SELECT * FROM orders WHERE customer = \'{customer}\'"', "rows = db.execute(query).fetchall()"],
         ['rows = db.execute("SELECT * FROM orders WHERE customer = ?", (customer,)).fetchall()']),
    case("good", "yaml safe_load", "CWE-502", "unsafe yaml.load on request data", "orders.py",
         ["data = yaml.load(request.data, Loader=yaml.Loader)"], ["data = yaml.safe_load(request.data)"]),
    case("good", "command list args", "CWE-78", "subprocess with shell=True and user input", "orders.py",
         ['subprocess.run(f"tar -czf {archive} -C {INVOICE_DIR} .", shell=True, check=True)'],
         ['if not re.fullmatch(r"[A-Za-z0-9_-]+", name): abort(400)',
          'subprocess.run(["tar", "-czf", archive, "-C", INVOICE_DIR, "."], check=True)']),
    case("good", "path send_from_directory", "CWE-22", "path traversal through send_file", "orders.py",
         ["return send_file(os.path.join(INVOICE_DIR, name))"], ["return send_from_directory(INVOICE_DIR, name)"]),
    case("good", "scrypt salted password", "CWE-327", "MD5 used to hash passwords", "app.py",
         ["return hashlib.md5(password.encode()).hexdigest()"],
         ["salt = os.urandom(16)", "digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)",
          'return f"scrypt${salt.hex()}${digest.hex()}"']),
    case("good", "remove verify=False", "CWE-295", "TLS certificate verification disabled", "orders.py",
         ["resp = requests.post(WEBHOOK_URL, json=payload, timeout=5, verify=False)"],
         ["resp = requests.post(WEBHOOK_URL, json=payload, timeout=5)"]),
    case("good", "secret from environment", "CWE-798", "hard-coded API key", "orders.py",
         ['api_key = "kT9vQ2mXr7LbN4wZc8HpY1sJd5FgA3eU"'], ['api_key = os.environ["PAYMENTS_API_KEY"]']),
    case("good", "redirect rebuilt from path", "CWE-601", "open redirect from request value", "app.py",
         ['return redirect(request.args.get("next", "/"))'],
         ['parsed = urlparse(request.args.get("next", "/"))',
          'if parsed.netloc and parsed.netloc != request.host: abort(403)',
          'return redirect(parsed.path or "/")']),
    # ---- changes that look like fixes but are not
    case("bad", "md5 -> unsalted sha256", "CWE-327", "MD5 used to hash passwords", "app.py",
         ["return hashlib.md5(password.encode()).hexdigest()"], ["return hashlib.sha256(password.encode()).hexdigest()"],
         review="the change replaces MD5 with a stronger hash"),
    case("bad", "silence with nosec", "CWE-89", "string-interpolated SQL query", "orders.py",
         ['query = f"SELECT * FROM orders WHERE customer = \'{customer}\'"'],
         ['query = f"SELECT * FROM orders WHERE customer = \'{customer}\'"  # nosec nosemgrep']),
    case("bad", "string replace as sanitiser", "CWE-89", "string-interpolated SQL query", "orders.py",
         ['query = f"SELECT * FROM orders WHERE customer = \'{customer}\'"'],
         ['customer = customer.replace("\'", "")',
          'query = f"SELECT * FROM orders WHERE customer = \'{customer}\'"']),
    case("bad", "swallow the error", "CWE-502", "unsafe yaml.load on request data", "orders.py",
         ["data = yaml.load(request.data, Loader=yaml.Loader)"],
         ["try:", "    data = yaml.load(request.data, Loader=yaml.Loader)", "except Exception:", "    data = {}"]),
    case("bad", "shell kept, quote one value", "CWE-78", "subprocess with shell=True and user input", "orders.py",
         ['subprocess.run(f"tar -czf {archive} -C {INVOICE_DIR} .", shell=True, check=True)'],
         ['subprocess.run(f"tar -czf {archive} -C {INVOICE_DIR} .", shell=True, check=True)  # name is trusted']),
    case("bad", "startswith path check", "CWE-22", "path traversal through send_file", "orders.py",
         ["return send_file(os.path.join(INVOICE_DIR, name))"],
         ['if not name.startswith("INV-"): abort(404)', "return send_file(os.path.join(INVOICE_DIR, name))"]),
    case("bad", "secret just moved", "CWE-798", "hard-coded API key", "orders.py",
         ['api_key = "kT9vQ2mXr7LbN4wZc8HpY1sJd5FgA3eU"'],
         ['DEFAULT_KEY = "kT9vQ2mXr7LbN4wZc8HpY1sJd5FgA3eU"', "api_key = os.environ.get('K', DEFAULT_KEY)"]),
    case("bad", "delete the feature", "CWE-502", "unsafe yaml.load on request data", "orders.py",
         ["data = yaml.load(request.data, Loader=yaml.Loader)", "items = data.get('orders', [])"],
         ["items = []"]),
]


def main() -> int:
    cfg = load_config(os.path.join(ROOT, "config.yaml"))
    laya = LayaClient(model=cfg.laya_model)
    rows = []
    for label, name, finding, diff, review in CASES:
        v = ValidationResult(finding=finding, clean=True, test_output="9 passed", validated=True,
                             attempts=1, fix_diff=diff, review=review)
        score = fix_trust(laya, finding, v)
        rows.append((label, name, score))
        print(f"{label:4} {name:28} {score}", flush=True)
    good = [s for l, _, s in rows if l == "good" and s is not None]
    bad = [s for l, _, s in rows if l == "bad" and s is not None]
    mean = lambda xs: sum(xs) / len(xs) if xs else float("nan")
    # Fraction of (good, bad) pairs where the good fix scores higher: 0.5 is a coin flip.
    pairs = [(g > b) + 0.5 * (g == b) for g in good for b in bad]
    print(f"\nmean good {mean(good):.3f} | mean bad {mean(bad):.3f} | "
          f"good > bad in {sum(pairs) / len(pairs):.0%} of pairs (50% = no signal)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
