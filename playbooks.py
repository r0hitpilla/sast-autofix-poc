"""Known-good remediation for classes of finding the model gets wrong.

A general instruction ("fix the weakness") lets the model pick the smallest
edit that silences the scanner: swapping MD5 for SHA-256 is one line and
passes the rule, but it is still wrong for passwords. A playbook says what a
correct fix contains, so the model implements that instead of the shortcut.
"""

import re

PASSWORD_HASHING = (
    "This code stores or checks a password. A fast or unsalted hash (MD5, SHA-1, "
    "SHA-256, SHA-512 on their own) is not acceptable, even salted SHA-256. Use "
    "the standard library's hashlib.scrypt with a random per-user salt:\n"
    "- On registration: salt = os.urandom(16); digest = hashlib.scrypt("
    "password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32). Store the salt "
    "and digest together, e.g. f\"scrypt${salt.hex()}${digest.hex()}\".\n"
    "- On login: split the stored value, recompute the digest with the same salt "
    "and parameters, and compare with hmac.compare_digest (that function is in "
    "hmac, not hashlib).\n"
    "The salt must be stored and checked. A fix that only changes the hash "
    "function, with no salt, is not a fix. Keep the existing hash and check "
    "functions with the same names and signatures, and put the new format inside "
    "them: then every caller (registration, login) keeps working unchanged and "
    "doesn't need editing. Change only lines you were shown."
)

DEPENDENCY_VULNERABILITY = (
    "A declared dependency has a known vulnerability. Raise its minimum version "
    "in the requirements file to the first fixed version named in the finding "
    "(or a later release). Change only that line. Do not remove the package."
)

HARD_CODED_SECRET = (
    "A credential is written into the source. Remove the literal value and read "
    "it from the environment instead, failing clearly if it is missing, e.g. "
    "os.environ[\"NAME\"]. Read it inside the function that uses it, not at the top "
    "of the module, so importing the module still works when the variable is unset. "
    "Do not keep the value anywhere in the file, including comments and tests."
)

OPEN_REDIRECT = (
    "Never pass a request value to redirect() as it is. Parse it with "
    "urllib.parse.urlparse and accept it only when it has no scheme and no host "
    "(a relative path) or its host equals request.host. Then redirect to a target "
    "REBUILT from the parsed parts, for example parsed.path plus \"?\" and "
    "parsed.query when there is a query, never to the original string. Otherwise "
    "redirect to \"/\" or call abort(400). Add the urlparse import as its own edit "
    "block at the top of the file and change nothing else."
)

SQL_INJECTION = (
    "Use a parameterized query: write ? placeholders in the SQL text and pass the "
    "values as a tuple, e.g. conn.execute(\"SELECT ... WHERE customer = ?\", "
    "(customer,)). Never build SQL with f-strings, %, + or .format. For LIKE, put "
    "the wildcards in the parameter value (\"%\" + term + \"%\"), not in the SQL. "
    "The SQL text must be a constant string."
)

COMMAND_INJECTION = (
    "Do not use shell=True and do not build a command string. Pass the program and "
    "its arguments as a list, e.g. subprocess.run([\"tar\", \"-czf\", archive, \"-C\", "
    "directory, \".\"], check=True). A value from the request that becomes part of a "
    "file name or argument must be validated first: allow only letters, digits, "
    "\"-\" and \"_\" (re.fullmatch) and call abort(400) otherwise."
)

UNSAFE_YAML = (
    "Use yaml.safe_load(...) and drop the Loader argument. safe_load builds only "
    "plain data (dicts, lists, strings, numbers)."
)

TEMPLATE_INJECTION = (
    "Never put request data inside a template string or an f-string returned as "
    "HTML, and do not use render_template_string at all: the scanner flags every "
    "use of it. Put the HTML in a template FILE, created with a NEW FILE block "
    "(templates/<name>.html, with {{ variable }} for each value, which is escaped "
    "automatically), and return render_template(\"<name>.html\", variable=value). "
    "Add render_template to the existing flask import with its own edit block. For "
    "HTML that must stay in Python, wrap every request-derived value in "
    "markupsafe.escape(...)."
)

PATH_TRAVERSAL = (
    "Serve files only from one fixed directory with flask.send_from_directory("
    "directory, filename), which refuses any path outside it. Do not join request "
    "input into a path for send_file or open(). Add the send_from_directory import "
    "as its own edit block at the top of the file."
)

TLS_VERIFICATION = (
    "Remove verify=False so certificates are checked (the default). Do not disable "
    "certificate verification; if a private CA is needed, pass verify=\"/path/ca.pem\"."
)

def _cwe(finding) -> str:
    """"CWE-601" from "CWE-601: URL Redirection ...", else ""."""
    return (finding.cwe or "").split(":")[0].strip().upper()


_PASSWORD_HINT = re.compile(r"password|passwd|pwd", re.IGNORECASE)
_WEAK_HASH = re.compile(r"\b(md5|sha1|sha224|sha256|sha384|sha512)\b", re.IGNORECASE)
# CWE-916 is "password hash with insufficient effort": a password by definition.
_PASSWORD_CWES = {"CWE-916"}


def guidance_for(finding) -> str:
    """Playbook text for this finding, or "" when none applies."""
    if finding.rule_id.startswith("osv."):
        return DEPENDENCY_VULNERABILITY
    if finding.rule_id.startswith("gitleaks."):
        return HARD_CODED_SECRET
    is_password_code = _cwe(finding) in _PASSWORD_CWES or bool(_PASSWORD_HINT.search(finding.snippet or ""))
    if is_password_code and _WEAK_HASH.search(f"{finding.snippet}\n{finding.message}"):
        return PASSWORD_HASHING

    # Semgrep sometimes files a rule under a neighbouring CWE (tainted-sql-string
    # is CWE-704), so the rule name counts as well as the CWE.
    cwe, rule = _cwe(finding), finding.rule_id.lower()
    code = f"{finding.snippet}\n{finding.message}".lower()
    if cwe == "CWE-601" or "open-redirect" in rule:
        return OPEN_REDIRECT
    if cwe == "CWE-89" or "sql-injection" in rule or "tainted-sql" in rule:
        return SQL_INJECTION
    if cwe == "CWE-78" or "subprocess" in rule or "command-injection" in rule:
        return COMMAND_INJECTION
    if cwe == "CWE-502" and ("yaml" in rule or "yaml.load" in code):
        return UNSAFE_YAML
    if cwe in ("CWE-79", "CWE-96") or "render-template-string" in rule or "raw-html" in rule:
        return TEMPLATE_INJECTION
    if cwe == "CWE-22" or "path-traversal" in rule:
        return PATH_TRAVERSAL
    if cwe == "CWE-295" or "cert" in rule and "valid" in rule:
        return TLS_VERIFICATION
    return ""
