from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    cwe: str
    message: str
    snippet: str


@dataclass
class TriageResult:
    finding: Finding
    llm_reasoning: str
    laya_score: float
    route: str  # "fix" | "review" | "reject"


@dataclass
class FixResult:
    finding: Finding
    diff: str
    applied: bool
    branch: str


@dataclass
class ValidationResult:
    finding: Finding
    clean: bool
    test_output: str
    validated: bool
