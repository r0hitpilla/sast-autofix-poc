"""What a security fix must never add, whatever the model was told.

A fix written by a model that has read untrusted code could carry a payload:
a network call home, a shell command, eval of a string, or a file that runs
by itself (a pytest conftest.py that makes the tests pass, a .pth file that
runs on every interpreter start). None of these is ever needed to fix a
finding, so a fix that adds one is refused and retried, told why.

Only what the fix ADDS counts: a file that already used subprocess may still
use it after the fix (fixing shell=True, for example).
"""

import ast
import os
import re

# Dotted names: a module counts if it is one of these or inside one.
# urllib.parse and http.cookies only parse text, so they are not listed.
RISKY_MODULES = {
    "socket": "network access", "ssl": "network access", "http.client": "network access",
    "http.server": "network access", "urllib.request": "network access", "urllib3": "network access",
    "requests": "network access", "httpx": "network access",
    "aiohttp": "network access", "ftplib": "network access", "smtplib": "network access",
    "telnetlib": "network access", "paramiko": "network access",
    "subprocess": "running commands", "pty": "running commands",
    "ctypes": "native code", "cffi": "native code",
    "pickle": "unsafe deserialization", "marshal": "unsafe deserialization", "shelve": "unsafe deserialization",
}
RISKY_CALLS = {
    "eval": "eval of a string", "exec": "exec of a string", "compile": "compiling code",
    "__import__": "dynamic import",
    "os.system": "running commands", "os.popen": "running commands", "os.execv": "running commands",
    "os.execl": "running commands", "os.spawnl": "running commands", "os.spawnv": "running commands",
    "importlib.import_module": "dynamic import",
}
# Files Python or pytest run without being imported by the project's code.
AUTO_RUN_FILES = {"conftest.py", "sitecustomize.py", "usercustomize.py", "setup.py", "pytest.ini",
                  "tox.ini", "setup.cfg", "pyproject.toml", "noxfile.py", "Makefile", "Dockerfile"}
AUTO_RUN_SUFFIXES = (".pth",)


def _dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def capabilities(source: str | None) -> set[str]:
    """Risky things a Python source does: 'module:x' and 'call:y' entries."""
    if not source:
        return set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    found = set()

    def check(module: str) -> None:
        for risky in RISKY_MODULES:
            if module == risky or module.startswith(risky + "."):
                found.add(f"module:{risky}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                check(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            check(node.module)
            for alias in node.names:  # from urllib import request
                check(f"{node.module}.{alias.name}")
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name in RISKY_CALLS:
                found.add(f"call:{name}")
    return found


def describe(cap: str) -> str:
    kind, name = cap.split(":", 1)
    why = RISKY_MODULES.get(name) if kind == "module" else RISKY_CALLS.get(name)
    return f"{'import of ' if kind == 'module' else ''}{name} ({why})"


# Comments that make a scanner skip a line. Adding one makes the rescan go clean
# without fixing anything, so a fix may never add one.
SUPPRESSION = re.compile(r"(#|//)\s*(nosec|nosemgrep|nosonar|lgtm\b|noqa:\s*S\d)", re.IGNORECASE)


def added_risks(file: str, before: str | None, after: str | None) -> list[str]:
    problems = []
    if len(SUPPRESSION.findall(after or "")) > len(SUPPRESSION.findall(before or "")):
        problems.append("the fix adds a scanner-suppression comment (nosec, nosemgrep...), "
                        "which hides the finding instead of fixing it")
    if file.endswith(".py"):
        new = capabilities(after) - capabilities(before)
        problems += [f"the fix adds {describe(c)}, which a security fix never needs" for c in sorted(new)]
    return problems


def forbidden_new_file(path: str) -> str | None:
    name = os.path.basename(path)
    if name in AUTO_RUN_FILES or name.endswith(AUTO_RUN_SUFFIXES):
        return f"{path}: a fix may not create {name}, which runs on its own or changes how tests run"
    return None
