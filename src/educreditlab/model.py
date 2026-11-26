"""Validate and normalize the schema used for policies, transcripts and receipts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import date
from pathlib import Path
from tempfile import NamedTemporaryFile

SCHEMA = 1
GRADES = {
    grade: rank
    for rank, grade in enumerate(
        ("F", "D-", "D", "D+", "C-", "C", "C+", "B-", "B", "B+", "A-", "A", "A+")
    )
}
UNRANKED = frozenset({"P", "NP", "W", "I"})
ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,79}")
HEX = re.compile(r"[0-9a-f]{64}")


class LabError(ValueError):
    """Invalid input or a lab workflow that cannot be completed safely."""


def canonical(document):
    """Stable JSON for the v1 schema, whose signed values use integers only."""
    try:
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise LabError("Document cannot be encoded as canonical UTF-8 JSON") from exc


def digest(document):
    return hashlib.sha256(canonical(document)).hexdigest()


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise LabError(f"Duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _reject_number(value):
    raise LabError(f"Use integers for numbers in this schema: {value}")


def loads(data):
    try:
        return json.loads(data, object_pairs_hook=_unique_pairs, parse_float=_reject_number,
                          parse_constant=_reject_number)
    except LabError:
        raise
    except (ValueError, RecursionError) as exc:
        raise LabError(f"Invalid JSON: {exc}") from exc


def read_json(path):
    return loads(Path(path).read_bytes())


def write_json(path, data):
    write_text(path, json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + "\n")


def write_text(path, value):
    write_bytes(path, value.encode("utf-8"))


def write_bytes(path, value):
    path = Path(path)
    temporary = None
    try:
        with NamedTemporaryFile(mode="wb", dir=path.parent,
                                prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def fields(obj, expected, context):
    if not isinstance(obj, dict) or set(obj) != set(expected.split()):
        raise LabError(f"{context} must contain exactly these fields: {expected}")
    return obj


def text(value, field, limit=500):
    if (not isinstance(value, str) or not value.strip() or len(value) > limit
            or any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise LabError(f"{field} must be nonempty text of at most {limit} characters")
    return value.strip()


def ident(value, field):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise LabError(f"{field} must be a lowercase identifier (letters, digits, . _ -)")
    return value


def hex_digest(value, field):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise LabError(f"{field} must be a 64-character lowercase hexadecimal digest")
    return value


def integer(value, field, low=0, high=1_000_000):
    if type(value) is not int or not low <= value <= high:
        raise LabError(f"{field} must be an integer in [{low}, {high}]")
    return value


def day(value, field):
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() == value:
            return value
    except (TypeError, ValueError):
        pass
    raise LabError(f"{field} must be a valid YYYY-MM-DD date")


def sequence(value, field, minimum, maximum):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise LabError(f"{field} must be an array with {minimum}–{maximum} items")
    return value


def code(value):
    return text(" ".join(text(value, "course code", 65).upper().split()), "normalized course code", 65)


def grade(value, *, unranked=False):
    if not isinstance(value, str) or (value not in GRADES and not (unranked and value in UNRANKED)):
        raise LabError(f"Unsupported grade: {value!r}")
    return value


def _unique_sorted(items, key, field):
    identifiers = [item[key] for item in items]
    if len(set(identifiers)) != len(identifiers):
        raise LabError(f"Duplicate {field}")
    return sorted(items, key=lambda item: item[key])


def normalize_policy(policy):
    fields(policy,
           "schema issuer receiver programme version valid_from valid_until unit cap group_caps "
           "kind provenance rules reuse", "policy")
    integer(policy["schema"], "policy schema", SCHEMA, SCHEMA)
    start = day(policy["valid_from"], "valid_from")
    end = day(policy["valid_until"], "valid_until")
    if end <= start:
        raise LabError("valid_until must follow valid_from")
    kind = policy["kind"]
    if kind not in ("historical-extract", "synthetic"):
        raise LabError("kind must be historical-extract or synthetic")
    provenance = fields(policy["provenance"], "title url note", "provenance")
    url = provenance["url"]
    if url is not None and (not isinstance(url, str) or not url.startswith("https://")):
        raise LabError("provenance URL must use https://")
    if kind == "historical-extract" and url is None:
        raise LabError("A historical extract requires a source URL")
    if not isinstance(policy["group_caps"], dict):
        raise LabError("group_caps must be an object")
    groups = {ident(key, "group"): integer(value, "group cap")
              for key, value in policy["group_caps"].items()}
    rules = []
    for rule in sequence(policy["rules"], "rules", 1, 120):
        fields(rule, "id label units group evidence options", "rule")
        options = []
        for option in sequence(rule["options"], "options", 1, 12):
            fields(option, "id all_of", "rule option")
            clauses = []
            for condition in sequence(option["all_of"], "all_of", 1, 12):
                fields(condition, "course min_grade", "option clause")
                clauses.append({"course": code(condition["course"]),
                                "min_grade": grade(condition["min_grade"])})
            options.append({"id": ident(option["id"], "option id"),
                            "all_of": _unique_sorted(clauses, "course", "course within an option")})
        rules.append({"id": ident(rule["id"], "rule id"), "label": text(rule["label"], "rule label"),
                      "units": integer(rule["units"], "target units", 0, 100_000),
                      "group": ident(rule["group"], "rule group"),
                      "evidence": text(rule["evidence"], "rule evidence"),
                      "options": _unique_sorted(options, "id", "option id within a rule")})
    if set(groups) - {rule["group"] for rule in rules}:
        raise LabError("All group caps must name a group used by a rule")
    rule_courses = {rule["id"]: {clause["course"] for option in rule["options"]
                                for clause in option["all_of"]} for rule in rules}
    reuse = []
    reuse_keys = set()
    for item in sequence(policy["reuse"], "reuse exceptions", 0, 100):
        fields(item, "course rules", "reuse exception")
        course = code(item["course"])
        pair = sorted(ident(value, "reuse rule") for value in sequence(item["rules"], "rules", 2, 2))
        if pair[0] == pair[1] or any(course not in rule_courses.get(rule, ()) for rule in pair):
            raise LabError("A reuse exception must match two distinct options that consume the course")
        key = (course, *pair)
        if key in reuse_keys:
            raise LabError("Duplicate reuse exception")
        reuse_keys.add(key)
        reuse.append({"course": course, "rules": pair})
    cap = policy["cap"]
    return {
        "schema": SCHEMA,
        **{key: ident(policy[key], key) for key in ("issuer", "receiver", "programme", "version")},
        "valid_from": start, "valid_until": end,
        "unit": text(policy["unit"], "unit", 40),
        "cap": None if cap is None else integer(cap, "cap"),
        "group_caps": groups, "kind": kind,
        "provenance": {"title": text(provenance["title"], "source title"),
                       "url": None if url is None else text(url, "source URL", 1000),
                       "note": text(provenance["note"], "source note", 1200)},
        "rules": _unique_sorted(rules, "id", "rule id"),
        "reuse": sorted(reuse, key=lambda row: (row["course"], row["rules"])),
    }


def normalize_transcript(transcript):
    fields(transcript, "schema issuer holder attempts", "transcript")
    integer(transcript["schema"], "transcript schema", SCHEMA, SCHEMA)
    attempts = []
    for attempt in sequence(transcript["attempts"], "attempts", 0, 300):
        fields(attempt, "id course grade completed_on", "course attempt")
        attempts.append({"id": ident(attempt["id"], "attempt id"), "course": code(attempt["course"]),
                         "grade": grade(attempt["grade"], unranked=True),
                         "completed_on": day(attempt["completed_on"], "completion date")})
    return {
        "schema": SCHEMA, "issuer": ident(transcript["issuer"], "issuer"),
        "holder": ident(transcript["holder"], "anonymous holder reference"),
        "attempts": _unique_sorted(attempts, "id", "attempt id"),
    }


def same_catalog(left, right):
    return all(left[field] == right[field] for field in ("issuer", "receiver", "programme"))


def applies(policy, issuer, receiver, programme, when):
    return (policy["issuer"] == issuer and policy["receiver"] == receiver
            and policy["programme"] == programme and policy["valid_from"] <= when < policy["valid_until"])


def select_policy(policies, issuer, receiver, programme, when):
    when = day(when, "as_of")
    matches = [p for p in policies if applies(p, issuer, receiver, programme, when)]
    if len(matches) != 1:
        raise LabError(f"Expected one applicable policy for {issuer} → {receiver}/{programme} "
                       f"on {when}; found {len(matches)}")
    return matches[0]

