"""What earlier runs found and tried for this repository's findings.

The dashboard keeps this history. Before triage and fixing, the pipeline
fetches it and passes each finding's record to the LLM as facts: it was
seen before, what the earlier verdict was, and what earlier fixes failed.
Without this, every run starts cold and repeats the same failed attempts.

If the dashboard is unreachable the pipeline runs without history, as it
did before. History is advice to the LLM, never a gate.
"""

import json
import sys
import urllib.parse
import urllib.request

from identity import finding_fingerprint


def fetch_history(base_url, repository: str, token=None, timeout: float = 2.0) -> dict:
    """fingerprint -> record, or {} when there is no dashboard to ask.

    `token` is the dashboard's machine token (SAST_HISTORY_TOKEN there,
    SAST_DASHBOARD_TOKEN here); without it the dashboard refuses the request.
    """
    if not isinstance(base_url, str) or not base_url or not repository:
        return {}
    query = urllib.parse.urlencode({"repository": repository})
    headers = {"Authorization": f"Bearer {token}"} if isinstance(token, str) and token else {}
    request = urllib.request.Request(f"{base_url.rstrip('/')}/api/history?{query}", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            items = json.load(resp)["items"]
    except (OSError, ValueError, KeyError) as exc:
        print(f"[history] dashboard unavailable, continuing without history: {exc}", file=sys.stderr)
        return {}
    return {item["fingerprint"]: item for item in items}


def finding_history(history: dict, repository: str, finding) -> dict | None:
    if not history:
        return None
    return history.get(finding_fingerprint(repository, finding.rule_id, finding.file, finding.snippet))


def history_note(record: dict | None) -> str:
    """Plain facts about earlier runs, for the prompt. "" when there are none."""
    if not record:
        return ""
    lines = [
        f"This same finding was reported by {record['occurrences']} earlier run(s), "
        f"first on {record['first_seen'][:10]}, most recently on {record['last_seen'][:10]}."
    ]
    if record.get("llm_label"):
        verdict = "TRUE POSITIVE" if record["llm_label"] == "tp" else "FALSE POSITIVE"
        lines.append(f"The earlier investigation concluded {verdict} (Laya {record['laya_score']:.2f}).")
    if record.get("fix_attempts"):
        if record.get("fix_validated"):
            lines.append("An earlier fix passed every check.")
        else:
            lines.append(f"Earlier fix attempts ({record['fix_attempts']}) did NOT pass validation.")
            if record.get("fix_failure"):
                lines.append(f"Why they failed: {record['fix_failure']}.")
            if record.get("fix_check_output"):
                lines.append(f"Last check output:\n{record['fix_check_output']}")
            if record.get("last_proposal"):
                lines.append(f"The last rejected proposal (do not repeat it):\n{record['last_proposal']}")
    return "\n".join(lines)
