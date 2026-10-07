from dataclasses import dataclass, field


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    cwe: str
    message: str
    snippet: str
    # Critical | High | Medium | Low — see scanner.severity_of.
    severity: str = "Medium"
    owasp: list[str] = field(default_factory=list)
    end_line: int | None = None
    # CVSS base score of a dependency advisory (osv findings); None elsewhere.
    cvss: float | None = None


@dataclass
class TriageResult:
    finding: Finding
    llm_reasoning: str
    laya_score: float
    route: str  # "fix" | "review" | "reject"
    # The (question, LLM answer) evidence Laya gathered before concluding,
    # in the order Laya asked for it.
    evidence: list[tuple[str, str]] = field(default_factory=list)
    # The numbered source the LLM was shown (for review UIs; "" if unread).
    context: str = ""
    # Prompt-injection markers found in that source (see injection.py). Any
    # marker means the finding can't be rejected, only fixed or reviewed.
    injection: list[str] = field(default_factory=list)


@dataclass
class FixResult:
    finding: Finding
    diff: str
    applied: bool
    branch: str
    # The file's content just before this finding's FIRST fix attempt. Retries
    # and reverts restore to this — not to HEAD — because earlier validated
    # fixes in the same file are still uncommitted in the working tree.
    baseline: str | None = None
    # Why the fix didn't apply, in words the LLM can act on during a retry.
    error: str = ""
    # New files this attempt created (e.g. a template), repo-relative.
    created_files: list[str] = field(default_factory=list)


@dataclass
class ValidationResult:
    finding: Finding
    clean: bool
    test_output: str
    validated: bool
    attempts: int = 1
    # Why the last attempt failed: "" when validated, else one of
    # "no usable fix" | "still flagged" | "breaks code or tests".
    failure: str = ""
    # The last fix the LLM proposed when none validated, shown to the
    # developer as an unverified suggestion.
    last_proposal: str = ""
    # Set when the fix was accepted with a caveat a reviewer should see,
    # e.g. the scanner still matches the pattern but triage judged it safe.
    note: str = ""
    # The accepted fix as a unified diff against the file just before it, so
    # PR hunks can be attributed to the fix that made them.
    fix_diff: str = ""
    # New files the accepted fix created; committed alongside the fix.
    created_files: list[str] = field(default_factory=list)


@dataclass
class Hunk:
    """One changed region of a file, in both old (base) and new (head) line numbers."""
    file: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)

    @property
    def new_end(self) -> int:
        return self.new_start + max(self.new_count, 1) - 1

    @property
    def old_end(self) -> int:
        return self.old_start + max(self.old_count, 1) - 1
