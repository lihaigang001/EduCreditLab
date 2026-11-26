"""Canonical, checkpoint-bound requirements for reviewing selected receipts."""

from .model import LabError, digest, fields, hex_digest, integer

PLAN_KIND = "educreditlab-review-plan"


def _requirements(rows):
    if not isinstance(rows, list) or not rows:
        raise LabError("A review plan must request at least one receipt")
    modes = {}
    previous = ""
    for row in rows:
        fields(row, "receipt_sha256 mode", "review plan requirement")
        reference = hex_digest(row["receipt_sha256"], "planned receipt commitment")
        if reference <= previous:
            raise LabError("Review plan receipt commitments must be unique and increasing")
        mode = row["mode"]
        if mode not in ("anchor", "replay"):
            raise LabError("Review plan mode must be anchor or replay")
        modes[reference] = mode
        previous = reference
    return modes


def make_review_plan(manifest_sha256, checkpoint_sha256, *, replay=(), anchor=()):
    rows = [{"receipt_sha256": hex_digest(reference, "planned receipt commitment"), "mode": mode}
            for mode, references in (("replay", replay), ("anchor", anchor)) for reference in references]
    rows.sort(key=lambda row: row["receipt_sha256"])
    _requirements(rows)
    return {
        "schema": 1, "kind": PLAN_KIND,
        "manifest_sha256": hex_digest(manifest_sha256, "planned manifest fingerprint"),
        "checkpoint_sha256": hex_digest(checkpoint_sha256, "planned checkpoint fingerprint"),
        "requirements": rows,
    }


def validate_review_plan(plan, trusted_plan, manifest_sha256, checkpoint_sha256):
    """Return the exact modes after checking the externally agreed plan fingerprint."""
    if trusted_plan is None:
        raise LabError("Plan-bound proofs require an independently trusted review plan fingerprint")
    pinned = hex_digest(trusted_plan, "trusted review plan fingerprint")
    fields(plan, "schema kind manifest_sha256 checkpoint_sha256 requirements", "review plan")
    integer(plan["schema"], "review plan schema", 1, 1)
    if digest(plan) != pinned:
        raise LabError("Review plan does not match the independently trusted fingerprint")
    if (plan["kind"] != PLAN_KIND or plan["manifest_sha256"] != manifest_sha256
            or plan["checkpoint_sha256"] != checkpoint_sha256):
        raise LabError("Review plan is not bound to the selected manifest and checkpoint")
    return _requirements(plan["requirements"])
