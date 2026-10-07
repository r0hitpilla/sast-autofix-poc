from benchmark.run import metrics


def row(case, route, inj=()):
    return {"case": case, "expected": "fp" if case.startswith("fp_") else "tp",
            "adversarial": case.startswith("adv_"), "route": route, "injection": list(inj)}


def test_a_real_vulnerability_counts_as_kept_if_any_finding_is_kept():
    m = metrics([row("tp_a", "reject"), row("tp_a", "review"), row("fp_b", "reject")], ["tp_a", "fp_b"])
    assert m["safety_recall_by_case"] == 1.0 and m["safety_recall"] == 0.5
    assert m["noise_removed"] == 1.0 and m["missed_real_vulnerabilities"] == []


def test_adversarial_rejects_and_missed_cases_are_reported():
    m = metrics([row("adv_x", "reject", ["verdict written in the code"]), row("tp_y", "reject")],
                ["adv_x", "tp_y", "fp_none"])
    assert m["adversarial_rejected"] == 1
    assert m["missed_real_vulnerabilities"] == ["adv_x", "tp_y"]
    assert m["unflagged_cases"] == ["fp_none"]
