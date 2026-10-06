"""Catch references a fix invents: imports that resolve to nothing, and
dependency versions that were never published.

A model that says `import fastjson` or pins `Flask==3.9.9` produces code that
looks plausible and fails at runtime or at install time. Compiling the file
won't catch either, so this checks each new reference against what really
exists: the standard library, the project's declared dependencies, local
modules, and the package index.
"""

import ast
import importlib
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Import name differs from the distribution name on PyPI.
IMPORT_NAME_OVERRIDES = {
    "pyyaml": "yaml",
    "pygithub": "github",
    "gitpython": "git",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "python-dateutil": "dateutil",
    "scikit-learn": "sklearn",
}

REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([0-9][^\s,;#]*)?"
)


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def declared_import_names(requirements_text: str) -> set[str]:
    """Import names provided by the project's declared requirements."""
    names = set()
    for line in requirements_text.splitlines():
        match = REQUIREMENT_RE.match(line)
        if not match:
            continue
        dist = _normalise(match.group(1))
        names.add(IMPORT_NAME_OVERRIDES.get(dist, dist.replace("-", "_")))
    return names


def _imported_modules(source: str) -> set[str]:
    """Top-level module names a Python source imports (relative imports excluded)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    return modules


# Importing these has side effects (a browser, a printout), so they are never imported to check.
_NEVER_IMPORT = {"antigravity", "this"}


def _module_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> stdlib module, for `import hashlib` and `import hashlib as h`."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in sys.stdlib_module_names:
                    aliases[alias.asname or alias.name.split(".")[0]] = alias.name
    return aliases


def _stdlib_attributes(source: str) -> set[tuple[str, str]]:
    """(module, attribute) pairs a source uses on imported stdlib modules."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    aliases = _module_aliases(tree)
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            used.add((aliases[node.value.id], node.attr))
    return used


def unknown_stdlib_attributes(file: str, before: str | None, after: str | None) -> list[str]:
    """Attributes the fix ADDED to a stdlib module that the module doesn't have.

    `hashlib.compare_digest` looks right and is wrong (it lives in `hmac`). It
    fails at runtime only on the path that calls it, so tests report a vague
    failure and the model never learns the cause.
    """
    if not file.endswith(".py") or after is None:
        return []
    added = _stdlib_attributes(after) - (_stdlib_attributes(before) if before else set())
    problems = []
    for module_name, attribute in sorted(added):
        if module_name in _NEVER_IMPORT:
            continue
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue  # platform-specific stdlib module; not this check's job
        if not hasattr(module, attribute):
            problems.append(f"'{module_name}.{attribute}' does not exist in the standard library")
    return problems


def _local_module(repo_dir: str | None, name: str) -> bool:
    if repo_dir is None:
        return False
    return (
        os.path.exists(os.path.join(repo_dir, f"{name}.py"))
        or os.path.isdir(os.path.join(repo_dir, name))
    )


def unresolved_imports(
    file: str, before: str | None, after: str | None,
    repo_dir: str | None, requirements_text: str,
) -> list[str]:
    """Imports the fix ADDED that resolve to nothing. Imports the file already
    had are not held against the fix."""
    if not file.endswith(".py") or after is None:
        return []
    added = _imported_modules(after) - (_imported_modules(before) if before else set())
    known = declared_import_names(requirements_text) | set(sys.stdlib_module_names)
    problems = []
    for name in sorted(added):
        if name in known or _local_module(repo_dir, name):
            continue
        problems.append(
            f"import '{name}' does not exist: it is not in the standard library, "
            "the declared requirements, or the repository"
        )
    return problems


def pypi_version_exists(name: str, version: str) -> bool | None:
    """True/False from the package index; None when it can't be reached.

    An unreachable index is not evidence the version is fake, so the caller
    decides what to do with None rather than rejecting the fix outright.
    """
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            json.load(response)
            return True
    except urllib.error.HTTPError as exc:
        return False if exc.code == 404 else None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def _pins(text: str) -> dict[str, str]:
    pins = {}
    for line in text.splitlines():
        match = REQUIREMENT_RE.match(line)
        if match and match.group(2):
            pins[_normalise(match.group(1))] = match.group(2)
    return pins


def unpublished_versions(before: str | None, after: str | None, version_exists=pypi_version_exists) -> list[str]:
    """Versions the fix ADDED to a requirements file that PyPI doesn't have."""
    if after is None:
        return []
    old = _pins(before or "")
    problems = []
    for name, version in _pins(after).items():
        if old.get(name) == version:
            continue
        if version_exists(name, version) is False:
            problems.append(f"{name} {version} is not a published version on PyPI")
    return problems


def check_references(
    file: str, before: str | None, after: str | None, repo_dir: str | None,
    requirements_text: str, version_exists=pypi_version_exists,
) -> list[str]:
    """Every invented reference the fix introduced, as human-readable problems."""
    if file.endswith(".py"):
        return (
            unresolved_imports(file, before, after, repo_dir, requirements_text)
            + unknown_stdlib_attributes(file, before, after)
        )
    if os.path.basename(file) in ("requirements.txt", "requirements-dev.txt"):
        return unpublished_versions(before, after, version_exists)
    return []
