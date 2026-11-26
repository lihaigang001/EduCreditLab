"""Generate feasible course bundles and allocate them with a binary linear model."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from itertools import combinations
from time import monotonic

import numpy as np
from scipy.optimize import Bounds, LinearConstraint, milp
from scipy.sparse import coo_matrix, csr_matrix, vstack

from .model import GRADES, LabError, applies, day, digest, normalize_policy, normalize_transcript

METHOD_VERSION = "1.0.0"


@dataclass(frozen=True)
class Candidate:
    rule: str
    option: str
    group: str
    units: int
    courses: tuple[str, ...]


def _check_clause(clause, attempts):
    threshold = GRADES[clause["min_grade"]]
    days = attempts.get(clause["course"], [])
    ranked = [attempt for attempt in days if attempt["grade"] in GRADES]
    best = max(ranked, key=lambda item: (GRADES[item["grade"]], item["completed_on"], item["id"]),
               default=None)
    if best:
        state = "eligible" if GRADES[best["grade"]] >= threshold else "grade_below_minimum"
    else:
        state = "unranked_grade" if days else "no_completed_attempt"
    return {**clause, "state": state, "attempt": best if best else None}


def _prepare(policy, transcript, when):
    attempts = defaultdict(list)
    for attempt in transcript["attempts"]:
        if attempt["completed_on"] <= when:
            attempts[attempt["course"]].append(attempt)
    checks = {}
    candidates = []
    for rule in policy["rules"]:
        options = []
        for option in rule["options"]:
            clauses = [_check_clause(clause, attempts) for clause in option["all_of"]]
            eligible = all(clause["state"] == "eligible" for clause in clauses)
            options.append({"id": option["id"], "eligible": eligible, "clauses": clauses})
            if eligible:
                courses = tuple(clause["course"] for clause in clauses)
                candidates.append(Candidate(rule["id"], option["id"], rule["group"],
                                            rule["units"], courses))
        checks[rule["id"]] = options
    return candidates, checks


def _reuse(policy):
    return {(item["course"], frozenset(item["rules"])) for item in policy["reuse"]}


def _constraints(candidates, policy):
    rows = defaultdict(list)
    upper = {}
    by_course = defaultdict(list)
    for index, entry in enumerate(candidates):
        key = ("rule", entry.rule)
        rows[key].append((index, 1))
        upper[key] = 1
        for course in entry.courses:
            by_course[course].append(index)
        if (cap := policy["group_caps"].get(entry.group)) is not None:
            key = ("group", entry.group)
            rows[key].append((index, entry.units))
            upper[key] = cap
        if policy["cap"] is not None:
            key = ("total", "")
            rows[key].append((index, entry.units))
            upper[key] = policy["cap"]
    allowed = _reuse(policy)
    exception_courses = {key[0] for key in allowed}
    for course, indices in by_course.items():
        if course not in exception_courses:
            key = ("course", course)
            rows[key] = [(index, 1) for index in indices]
            upper[key] = 1
            continue
        for left, right in combinations(indices, 2):
            pair = frozenset((candidates[left].rule, candidates[right].rule))
            if len(pair) == 2 and (course, pair) not in allowed:
                key = ("conflict", left, right)
                rows[key] = [(left, 1), (right, 1)]
                upper[key] = 1
    row_ix, col_ix, values = [], [], []
    for row, coefficients in enumerate(rows.values()):
        for column, value in coefficients:
            row_ix.append(row)
            col_ix.append(column)
            values.append(value)
    matrix = coo_matrix((values, (row_ix, col_ix)), shape=(len(rows), len(candidates))).tocsc()
    return matrix, np.zeros(len(rows)), np.array([upper[key] for key in rows], dtype=float)


def _optimal(candidates, policy, time_limit):
    if not candidates:
        return []
    count = len(candidates)
    size = len(policy["rules"])
    points = np.array([item.units * (size + 1) + 1 for item in candidates], dtype=float)
    matrix, lb, ub = _constraints(candidates, policy)
    lower_bounds, upper_bounds = np.zeros(count), np.ones(count)
    integrality = np.ones(count, dtype=np.uint8)
    deadline = monotonic() + time_limit

    def optimize(score, matrix, lb, ub):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise LabError("The solver exceeded its time limit")
        result = milp(-score, integrality=integrality, bounds=Bounds(lower_bounds, upper_bounds),
                      constraints=LinearConstraint(matrix, lb, ub),
                      options={"mip_rel_gap": 0.0, "time_limit": remaining})
        if result.status != 0 or result.x is None:
            raise LabError(f"The solver could not certify an optimum: {result.message}")
        rounded = np.rint(result.x)
        if (np.max(np.abs(result.x - rounded)) > 1e-6
                or np.any(rounded < lower_bounds) or np.any(rounded > upper_bounds)
                or np.any(matrix @ rounded < lb - 1e-7) or np.any(matrix @ rounded > ub + 1e-7)):
            raise LabError("The solver returned an invalid integer solution")
        return rounded

    solution = optimize(points, matrix, lb, ub)
    optimum = float(points @ solution)
    matrix = vstack([matrix, csr_matrix(points.reshape(1, -1))], format="csc")
    lb, ub = np.append(lb, optimum), np.append(ub, optimum)

    # A bounded powers-of-two objective gives exact lexicographic order within each
    # chunk. Freezing an earlier chunk keeps numerical weights small for long policies.
    for start in range(0, count, 20):
        end = min(count, start + 20)
        score = np.zeros(count)
        score[start:end] = [2 ** power for power in range(end - start - 1, -1, -1)]
        solution = optimize(score, matrix, lb, ub)
        lower_bounds[start:end] = upper_bounds[start:end] = solution[start:end]
    return [item for item, chosen in zip(candidates, solution) if chosen]


def _greedy(candidates, policy):
    selected, picked, used = [], set(), defaultdict(list)
    allowed = _reuse(policy)
    units, group_units = 0, defaultdict(int)
    for candidate in candidates:
        if candidate.rule in picked or any((course, frozenset((candidate.rule, owner))) not in allowed
                                            for course in candidate.courses for owner in used[course]):
            continue
        cap = policy["cap"]
        group_cap = policy["group_caps"].get(candidate.group)
        if cap is not None and units + candidate.units > cap:
            continue
        if group_cap is not None and group_units[candidate.group] + candidate.units > group_cap:
            continue
        selected.append(candidate)
        picked.add(candidate.rule)
        for course in candidate.courses:
            used[course].append(candidate.rule)
        units += candidate.units
        group_units[candidate.group] += candidate.units
    return selected


def _describe(policy, chosen, checks):
    selected = {item.rule: item for item in chosen}
    course_owners = defaultdict(list)
    allowed = _reuse(policy)
    group_units = defaultdict(int)
    for item in chosen:
        group_units[item.group] += item.units
        for course in item.courses:
            course_owners[course].append(item.rule)
    total = sum(item.units for item in chosen)
    rows = []
    for rule in policy["rules"]:
        item = selected.get(rule["id"])
        options = checks[rule["id"]]
        blockers = []
        if item is None:
            for option in options:
                if not option["eligible"]:
                    continue
                reused = sorted({owner for c in option["clauses"] for owner in course_owners[c["course"]]
                                 if (c["course"], frozenset((rule["id"], owner))) not in allowed})
                cap = policy["cap"]
                group_cap = policy["group_caps"].get(rule["group"])
                blockers.append({"option": option["id"], "competes_with": reused,
                                 "total_cap": cap is not None and total + rule["units"] > cap,
                                 "group_cap": group_cap is not None
                                 and group_units[rule["group"]] + rule["units"] > group_cap})
        status = "recognized" if item else ("allocation_conflict" if blockers else "requirements_unmet")
        rows.append({"id": rule["id"], "label": rule["label"], "group": rule["group"],
                     "status": status, "potential_units": rule["units"],
                     "selected_option": item.option if item else None,
                     "options": options, "allocation_blockers": blockers, "evidence": rule["evidence"]})
    return rows, total


def evaluate(policy, transcript, as_of, *, method="optimal", time_limit=15):
    """Return a deterministic decision with one explanation per target rule."""
    policy, transcript = normalize_policy(policy), normalize_transcript(transcript)
    when = day(as_of, "as_of")
    if not applies(policy, transcript["issuer"], policy["receiver"], policy["programme"], when):
        raise LabError("The transcript issuer and as_of date must match the policy scope")
    if method not in ("optimal", "greedy"):
        raise LabError("Method must be optimal or greedy")
    candidates, checks = _prepare(policy, transcript, when)
    chosen = _optimal(candidates, policy, time_limit) if method == "optimal" else _greedy(candidates, policy)
    rows, total = _describe(policy, chosen, checks)
    return {
        "schema": 1, "method": method, "method_version": METHOD_VERSION, "as_of": when,
        "issuer": policy["issuer"], "receiver": policy["receiver"], "programme": policy["programme"],
        "policy_version": policy["version"], "policy_sha256": digest(policy),
        "policy_kind": policy["kind"], "unit": policy["unit"],
        "recognized_units": total, "recognized_rules": len(chosen), "rules": rows,
    }

