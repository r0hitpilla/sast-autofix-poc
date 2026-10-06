"""Stable identity of a finding across CI runs, branches and repositories.

Shared by the pipeline (which writes it into each report) and the dashboard
(which backfills it for runs recorded before it existed), so both always
agree on what makes two findings the same.

Identity is the repository, the rule, the file and the flagged code with
whitespace collapsed. The line number is deliberately NOT part of it: the
line moves whenever code above it changes, and the same vulnerability would
then look like a new one every time someone edits the file.
"""

import hashlib


def normalise_code(snippet: str) -> str:
    return " ".join((snippet or "").split())


def distinct_locations(pairs) -> int:
    """How many distinct places in the code the (file, snippet) pairs cover.

    Several rules often flag the same code, so rule hits and findings differ.
    """
    return len({(file, normalise_code(snippet)) for file, snippet in pairs})


def finding_fingerprint(repository: str, rule_id: str, file: str, snippet: str) -> str:
    # \x1f (unit separator) cannot appear in these fields, so the parts can't
    # run together and collide ("a|b" + "c" vs "a" + "b|c").
    parts = [repository, rule_id, file, normalise_code(snippet)]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
