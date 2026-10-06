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
    "function, with no salt, is not a fix. Every place in this file that creates "
    "or checks a password hash must agree on the new format, so change all of "
    "them in the same reply."
)

DEPENDENCY_VULNERABILITY = (
    "A declared dependency has a known vulnerability. Raise its minimum version "
    "in the requirements file to the first fixed version named in the finding "
    "(or a later release). Change only that line. Do not remove the package."
)

HARD_CODED_SECRET = (
    "A credential is written into the source. Remove the literal value and read "
    "it from the environment instead, failing clearly if it is missing, e.g. "
    "os.environ[\"NAME\"]. Do not keep the value anywhere in the file, including "
    "comments and tests."
)

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
    is_password_code = finding.cwe in _PASSWORD_CWES or bool(_PASSWORD_HINT.search(finding.snippet or ""))
    if is_password_code and _WEAK_HASH.search(f"{finding.snippet}\n{finding.message}"):
        return PASSWORD_HASHING
    return ""
