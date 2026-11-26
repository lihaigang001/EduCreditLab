"""Reproducible measurements. Labels and allocation oracles are kept out of the solver."""

from __future__ import annotations

from copy import deepcopy
import csv
from itertools import product
from pathlib import Path
import json
import math
import platform
import random
import sqlite3
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter_ns

import cryptography
import numpy as np
import scipy

from . import __version__
from .lab import DEMO_AMENDMENT, Lab, bundled_data, verify_bundle
from .model import LabError, digest
from .solver import evaluate

AS_OF = "2023-06-15"
COURSES = (
    ("CS/IS 135", "B"), ("CS/IS 137", "C"), ("CS/IS 112", "B-"), ("MATH 103EH", "B"),
    ("MATH 104E", "C"), ("CS/IS 211", "C"), ("CS/IS 212", "C"), ("PHY 101", "B"), ("PHY 102", "B"),
)


def _transcript(name, courses):
    return {"schema": 1, "issuer": "glendale-cc", "holder": name, "attempts": [
        {"id": f"a-{index:03d}", "course": course, "grade": grade, "completed_on": "2023-05-24"}
        for index, (course, grade) in enumerate(courses)
    ]}


def _selected(decision):
    return sorted(rule["id"] for rule in decision["rules"] if rule["status"] == "recognized")


def _historical_labels(receiver, present):
    cpp, advanced, java, calculus1, calculus2, structures1, structures2, physics1, physics2 = present
    if receiver == "uc-irvine":
        # Calculus II in this grid has C, while the Irvine preparation fixture requires B.
        return {"ics-31-33": (cpp and advanced, 12), "ics-46": (structures1 and structures2, 4),
                "math-2a": (calculus1, 4), "physics-series": (physics1 and physics2, 10)}
    # The Java grade is B-; the linked historical preparation row requires B.
    return {"cse-020-021": (cpp, 0), "cse-022": (cpp or java, 4), "cse-030": (structures1, 4),
            "math-021": (calculus1, 4), "math-022": (calculus2, 4),
            "phys-008-008l": (physics1, 4), "phys-009-009l": (physics2, 4)}


def _historical_grid():
    rows = []
    historical = [p for p in bundled_data("policies.json") if p["kind"] == "historical-extract"]
    for index, present in enumerate(product((0, 1), repeat=len(COURSES))):
        mask = "".join(str(bit) for bit in present)
        transcript = _transcript(f"grid-{index:03d}", [row for row, keep in zip(COURSES, present) if keep])
        for policy in historical:
            labels = _historical_labels(policy["receiver"], present)
            expected = sorted(key for key, (include, _) in labels.items() if include)
            expected_units = sum(units * 100 for include, units in labels.values() if include)
            start = perf_counter_ns()
            result = evaluate(policy, transcript, AS_OF)
            milliseconds = (perf_counter_ns() - start) / 1e6
            observed = _selected(result)
            rows.append({"case": transcript["holder"], "mask": mask, "receiver": policy["receiver"],
                         "expected_rules": "|".join(expected), "observed_rules": "|".join(observed),
                         "expected_units_centi": expected_units,
                         "observed_units_centi": result["recognized_units"],
                         "matches": int(observed == expected and expected_units == result["recognized_units"]),
                         "solve_ms": round(milliseconds, 6)})
    return rows


def _temporal_grid(directory):
    lab = Lab(directory, "consortium")
    lab.seed()
    before = len(lab.ledger.prefix())
    after = lab.seed_amendment()["core"]["height"]
    grades = ("B", "B-", "C", "C-", "-")
    dates = ("2023-05-31", "2023-06-01", "2023-06-15", "2023-07-01")
    rows = []
    for index, (first, second, calculus) in enumerate(product(grades, grades, ("B", "C", "-"))):
        transcript = _transcript(f"temporal-{index:02d}", [
            (course, grade) for course, grade in zip(("CS/IS 135", "CS/IS 137", "MATH 103EH"),
                                                    (first, second, calculus)) if grade != "-"
        ])
        for as_of, height in product(dates, (before, after)):
            # This reference encodes the two example thresholds directly.
            july = as_of == "2023-07-01"
            june_revision = height == after and "2023-06-01" <= as_of < "2023-07-01"
            strict = july or june_revision
            course_ok = first == second == "B" if strict else (
                first in ("B", "B-", "C") and second in ("B", "B-", "C"))
            expected_rules = (["ics-31-33"] if course_ok else []) + (["math-2a"] if calculus == "B" else [])
            expected_units = 1200 * course_ok + 400 * (calculus == "B")
            expected_version = "sim-2023-07" if july else ("sim-ay2022-23-r2" if june_revision else "ay-2022-23")
            observed = lab.preview(transcript, "uc-irvine", "cse-bs", as_of, known_height=height)
            matches = (_selected(observed) == expected_rules and observed["recognized_units"] == expected_units
                       and observed["policy_version"] == expected_version)
            rows.append({"case": transcript["holder"], "programming_1": first, "programming_2": second,
                         "calculus": calculus, "effective_on": as_of, "knowledge_height": height,
                         "expected_version": expected_version, "observed_version": observed["policy_version"],
                         "expected_units_centi": expected_units, "observed_units_centi": observed["recognized_units"],
                         "expected_rules": "|".join(expected_rules), "observed_rules": "|".join(_selected(observed)),
                         "matches": int(matches)})
    return rows


def _allocation_case(rng, index):
    routes = [
        ("a-bundle", rng.choice([400, 500, 600, 700]), "core", [("A", "B")]),
        ("b-left", rng.choice([300, 400, 500]), "core", [("A",), ("C",)]),
        ("c-right", rng.choice([300, 400, 500]), "core", [("B",), ("D",)]),
        ("d-elective", rng.choice([100, 200, 300]), "elective", [("C",), ("D", "E")]),
    ]
    cap = rng.choice([700, 800, 900, 1000, None])
    core_cap = rng.choice([None, 600, 800, 900])
    course_set = set("ABCDE")
    if index % 3:
        course_set.remove(rng.choice("CDE"))
    policies = bundled_data("policies.json")
    policy = deepcopy(policies[-1])
    policy.update(version="allocation-grid", valid_from="2022-07-01", valid_until="2023-07-01",
                  cap=cap, group_caps={} if core_cap is None else {"core": core_cap})
    policy["rules"] = [
        {"id": name, "label": name, "units": units, "group": group, "evidence": "Synthetic case.",
         "options": [{"id": f"option-{i}", "all_of": [{"course": course, "min_grade": "C"}
                                                     for course in route]}
                     for i, route in enumerate(options)]}
        for name, units, group, options in routes
    ]
    transcript = _transcript(f"alloc-{index:02d}", [(course, "A") for course in sorted(course_set)])

    # Exhaustive oracle enumerates one selection per requirement including no allocation.
    feasible_sets = []
    choice_domains = [[None, *options] for _, _, _, options in routes]
    for choices in product(*choice_domains):
        used = [course for choice in choices if choice is not None for course in choice]
        if len(set(used)) != len(used) or not set(used) <= course_set:
            continue
        credits = sum(row[1] for row, choice in zip(routes, choices) if choice is not None)
        core = sum(row[1] for row, choice in zip(routes, choices)
                   if choice is not None and row[2] == "core")
        if (cap is None or credits <= cap) and (core_cap is None or core <= core_cap):
            feasible_sets.append((credits, sum(choice is not None for choice in choices)))
    return policy, transcript, max(feasible_sets)


def _allocations():
    rng = random.Random(20261122)
    rows = []
    for index in range(64):
        policy, transcript, oracle = _allocation_case(rng, index)
        optimal = evaluate(policy, transcript, AS_OF)
        greedy = evaluate(policy, transcript, AS_OF, method="greedy")
        rows.append({
            "case": transcript["holder"], "cap_centi": policy["cap"],
            "core_cap_centi": policy["group_caps"].get("core"),
            "oracle_units_centi": oracle[0], "oracle_rules": oracle[1],
            "optimal_units_centi": optimal["recognized_units"], "optimal_rules": optimal["recognized_rules"],
            "greedy_units_centi": greedy["recognized_units"], "greedy_rules": greedy["recognized_rules"],
            "optimal_rules_ids": "|".join(_selected(optimal)), "greedy_rules_ids": "|".join(_selected(greedy)),
        })
    return rows


def _rejected(work):
    try:
        work()
    except LabError:
        return True
    return False


def _ledger_trials(repeats, directory):
    measurements, scenarios = [], {}
    transcript = bundled_data("cases.json")[0]["transcript"]
    policies = bundled_data("policies.json")
    for mode in ("central", "consortium"):
        lab = Lab(directory / mode, mode)
        for policy in policies[:2]:
            lab.publish(policy)
        signed = lab.sign_transcript(transcript)
        warmup = lab.record(signed, "uc-irvine", "cse-bs", AS_OF)
        original = warmup["receipt_sha256"]
        lab.publish(policies[2])
        replay = verify_bundle(lab.bundle(original), lab.ledger.fingerprint)
        revised = lab.preview(transcript, "uc-irvine", "cse-bs", "2023-07-15")
        if (replay["decision"]["policy_version"] == revised["policy_version"]
                or replay["decision"]["recognized_units"] != 1600 or revised["recognized_units"] != 400):
            raise LabError("The benchmark did not reproduce the original and revised policy results")
        for index in range(repeats):
            start = perf_counter_ns()
            issuance = lab.record(signed, "uc-irvine", "cse-bs", AS_OF)
            milliseconds = (perf_counter_ns() - start) / 1e6
            replica = next(iter(lab.ledger.manifest["validators"]))
            bundle = lab.bundle(issuance["receipt_sha256"], replica)
            verify_start = perf_counter_ns()
            checked = verify_bundle(bundle, lab.ledger.fingerprint)
            verify_ms = (perf_counter_ns() - verify_start) / 1e6
            measurements.append({"mode": mode, "run": index + 1, "height": issuance["height"],
                                 "votes": len(issuance["votes"]), "record_ms": round(milliseconds, 6),
                                 "verify_ms": round(verify_ms, 6), "replayed": int(checked["replayed"])})
        bundle = lab.bundle(original)
        for mutation in ("receipt", "policy", "transcript", "quorum"):
            edited = deepcopy(bundle)
            if mutation == "receipt":
                edited["receipt"]["body"]["decision"]["recognized_units"] += 100
            elif mutation == "policy":
                edited["policy"]["rules"][0]["units"] += 100
            elif mutation == "transcript":
                edited["transcript"]["body"]["transcript"]["attempts"][0]["grade"] = "A"
            else:
                edited["chain"][-1]["votes"].clear()
            scenarios[f"{mode}_{mutation}_rejected"] = _rejected(
                lambda: verify_bundle(edited, lab.ledger.fingerprint))
        scenarios[f"{mode}_wrong_trust_rejected"] = _rejected(
            lambda: verify_bundle(bundle, "0" * 64))
        scenarios[f"{mode}_historical_replay_after_revision"] = replay["replayed"]

    peers = tuple(lab.ledger.manifest["validators"])
    # At the end of the loop lab is the four-validator reference network.
    one_out = lab.record(signed, "uc-irvine", "cse-bs", AS_OF, available=peers[:3])
    scenarios["consortium_one_unavailable_commits"] = len(one_out["votes"]) == 3
    before = len(lab.ledger.prefix())
    nonce = "d4" * 32
    scenarios["consortium_two_unavailable_stops"] = _rejected(
        lambda: lab.record(signed, "uc-irvine", "cse-bs", AS_OF, available=peers[:2], nonce=nonce)
    ) and len(lab.ledger.prefix()) == before
    synced = lab.ledger.sync()
    retry = lab.record(signed, "uc-irvine", "cse-bs", AS_OF, nonce=nonce)
    scenarios["consortium_pending_recovery_is_idempotent"] = (
        synced["height"] == retry["height"] == before + 1
        and all(len(lab.ledger.prefix(peer)) == synced["height"] for peer in peers)
    )
    return measurements, scenarios


def _latency(numbers):
    values = sorted(numbers)
    return {"p50": round(median(values), 3), "p95": round(values[math.ceil(len(values) * 0.95) - 1], 3)}


def _write_csv(path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run_benchmark(output, repeats=30):
    if not 5 <= repeats <= 200:
        raise LabError("Use 5–200 ledger repetitions")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    history, allocation = _historical_grid(), _allocations()
    with TemporaryDirectory() as directory:
        root = Path(directory)
        temporal = _temporal_grid(root / "revision")
        logs, scenarios = _ledger_trials(repeats, root)
    history_matches = sum(row["matches"] for row in history)
    temporal_matches = sum(row["matches"] for row in temporal)
    opt_correct = sum((r["oracle_units_centi"], r["oracle_rules"]) ==
                      (r["optimal_units_centi"], r["optimal_rules"]) for r in allocation)
    greedy_correct = sum((r["oracle_units_centi"], r["oracle_rules"]) ==
                         (r["greedy_units_centi"], r["greedy_rules"]) for r in allocation)
    if (history_matches != len(history) or temporal_matches != len(temporal) or opt_correct != len(allocation)
            or not all(scenarios.values()) or not all(row["replayed"] for row in logs)):
        raise LabError("A benchmark correctness criterion did not pass")
    cpu = platform.processor() or platform.machine()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        cpu = next((line.split(":", 1)[1].strip()
                    for line in cpuinfo.read_text().splitlines() if line.startswith("model name")), cpu)
    timing = {}
    for mode in ("central", "consortium"):
        values = [item for item in logs if item["mode"] == mode]
        timing[mode] = {
            "commits": len(values),
            "record_ms": _latency(row["record_ms"] for row in values),
            "verify_ms": _latency(row["verify_ms"] for row in values),
        }
    summary = {
        "software_version": __version__, "fixture_sha256": digest(bundled_data("policies.json")),
        "amendment_fixture_sha256": digest(bundled_data(DEMO_AMENDMENT)),
        "environment": {"python": platform.python_version(), "numpy": np.__version__,
                        "scipy": scipy.__version__, "cryptography": cryptography.__version__,
                        "sqlite": sqlite3.sqlite_version, "os": platform.system(),
                        "machine": platform.machine(), "cpu": cpu},
        "historical_grid": {"synthetic_transcripts": len(history) // 2,
                            "policy_decisions": len(history), "exact_matches": history_matches},
        "temporal_grid": {"synthetic_transcripts": len({row["case"] for row in temporal}),
                          "assessment_dates": len({row["effective_on"] for row in temporal}),
                          "knowledge_views": len({row["knowledge_height"] for row in temporal}),
                          "policy_decisions": len(temporal), "exact_matches": temporal_matches},
        "allocation": {"instances": len(allocation), "optimal_matches": opt_correct,
                       "greedy_matches": greedy_correct,
                       "greedy_lost_units_centi": sum(r["optimal_units_centi"] - r["greedy_units_centi"]
                                                    for r in allocation)},
        "replay": {"exact_matches": sum(row["replayed"] for row in logs), "receipts": len(logs)},
        "ledger_latency": timing, "scenarios": scenarios,
    }
    for name, rows in [("historical_grid.csv", history), ("temporal_grid.csv", temporal), ("allocation_grid.csv", allocation),
                       ("ledger_samples.csv", logs)]:
        _write_csv(output / name, rows)
    (output / "benchmark_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary

