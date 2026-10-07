"""The security policy: what blocks a merge and what may be auto-fixed.

Shared by the pipeline (which enforces it) and the dashboard (where it is
edited and published as immutable versions).

Fail closed: when no policy applies, or the dashboard can't be reached, the
pipeline uses STRICT, which is how it behaved before policies existed: every
confirmed or uncertain finding blocks, and nothing a person decided clears
it. A policy can only relax that on purpose.
"""

import fnmatch
from dataclasses import dataclass, field

SEVERITIES = ("Critical", "High", "Medium", "Low")
ACTIONS = ("block", "review", "allow")  # block merge | review required | allow
# CI files are never auto-fixed whatever the policy says: GitHub refuses
# workflow edits pushed with the Actions token, and an LLM editing CI is where
# a prompt injection would do the most damage.
ALWAYS_NEVER_AUTOFIX = (".github/**",)


class PolicyError(ValueError):
    """The policy content is invalid. The message is shown to the editor."""


@dataclass(frozen=True)
class Policy:
    version: int | None = None
    severity_actions: dict = field(default_factory=lambda: {s: "block" for s in SEVERITIES})
    # When False, a person's decision clears only "review" findings, never "block" ones.
    decisions_clear_blocks: bool = False
    autofix: bool = True
    never_autofix: tuple = ()
    repositories: tuple = ("*",)
    branches: tuple = ("*",)

    def applies_to(self, repository: str, branch: str) -> bool:
        return (any(fnmatch.fnmatchcase(repository, p) for p in self.repositories)
                and any(fnmatch.fnmatchcase(branch, p) for p in self.branches))

    def action_for(self, severity: str) -> str:
        return self.severity_actions.get(severity, "block")

    def blocks(self, severity: str, decision: str | None) -> bool:
        """Whether a confirmed (or uncertain) finding blocks the merge gate."""
        action = self.action_for(severity)
        if action == "allow":
            return False
        if decision and (action == "review" or self.decisions_clear_blocks):
            return False
        return True

    def may_autofix(self, path: str) -> bool:
        if any(_path_match(path, p) for p in ALWAYS_NEVER_AUTOFIX):
            return False
        return self.autofix and not any(_path_match(path, p) for p in self.never_autofix)

    def to_dict(self) -> dict:
        return {"version": self.version, "severity_actions": dict(self.severity_actions),
                "decisions_clear_blocks": self.decisions_clear_blocks, "autofix": self.autofix,
                "never_autofix": list(self.never_autofix), "repositories": list(self.repositories),
                "branches": list(self.branches)}


STRICT = Policy()


def _path_match(path: str, pattern: str) -> bool:
    """Glob where ** spans directories: 'src/**' matches 'src/a/b.py'."""
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/") or fnmatch.fnmatchcase(path, pattern)
    return fnmatch.fnmatchcase(path, pattern)


def _patterns(value, label: str) -> tuple:
    if isinstance(value, str):
        value = [v for v in value.split(",")]
    items = tuple(p.strip() for p in (value or []) if str(p).strip())
    for p in items:
        if len(p) > 200 or "\n" in p:
            raise PolicyError(f"{label}: pattern too long or multi-line")
    return items


def from_dict(data: dict, version: int | None = None) -> Policy:
    """Validate submitted or stored policy content."""
    if not isinstance(data, dict):
        raise PolicyError("policy must be an object")
    actions = data.get("severity_actions") or {}
    if set(actions) != set(SEVERITIES):
        raise PolicyError(f"severity_actions needs exactly: {', '.join(SEVERITIES)}")
    for severity, action in actions.items():
        if action not in ACTIONS:
            raise PolicyError(f"{severity}: action must be one of {', '.join(ACTIONS)}")
    repositories = _patterns(data.get("repositories", ["*"]), "repositories") or ("*",)
    branches = _patterns(data.get("branches", ["*"]), "branches") or ("*",)
    return Policy(
        version=version if version is not None else data.get("version"),
        severity_actions={s: actions[s] for s in SEVERITIES},
        decisions_clear_blocks=bool(data.get("decisions_clear_blocks", False)),
        autofix=bool(data.get("autofix", True)),
        never_autofix=_patterns(data.get("never_autofix", []), "never_autofix"),
        repositories=repositories,
        branches=branches,
    )
