"""Compare trusted reviewer policy views and verify portable evidence of divergence."""

from .model import LabError, digest, fields, integer
from .policy_history import _verified_change, _verified_history, _verified_revisions

DIVERGENCE_KIND = "educreditlab-review-policy-divergence"


def _describe_divergence(shared, left, right):
    if left["revision_sha256"] == right["revision_sha256"]:
        raise LabError("Divergence evidence requires two distinct successors of the shared revision")
    predecessor_keys = set(shared["policy"]["reviewer_sha256"])
    overlap = predecessor_keys.intersection(left["approver_sha256"], right["approver_sha256"])
    return {"shared_revision": shared["revision"], "shared_revision_sha256": shared["revision_sha256"],
            "divergent_revision": left["revision"], "left_successor_sha256": left["revision_sha256"],
            "right_successor_sha256": right["revision_sha256"],
            "shared_predecessor_approvers": sorted(overlap)}


def compare_policy_histories(left_history, right_history, trusted_initial, trusted_left, trusted_right):
    """Verify both complete histories against their independently obtained endpoint pins."""
    left = _verified_revisions(left_history, trusted_initial, trusted_left)
    right = _verified_revisions(right_history, trusted_initial, trusted_right)
    common = 0
    for left_revision, right_revision in zip(left, right):
        if left_revision["revision_sha256"] != right_revision["revision_sha256"]:
            break
        common += 1
    shared = left[common - 1]
    verdict = {"policy_comparison_verified": True, "initial_policy_sha256": trusted_initial,
               "shared_revision": shared["revision"], "shared_revision_sha256": shared["revision_sha256"],
               "left_latest_revision": len(left), "left_latest_revision_sha256": trusted_left,
               "right_latest_revision": len(right), "right_latest_revision_sha256": trusted_right}
    if common == len(left) == len(right):
        return {**verdict, "relationship": "identical"}, None
    if common == len(left):
        return {**verdict, "relationship": "left_prefix"}, None
    if common == len(right):
        return {**verdict, "relationship": "right_prefix"}, None
    evidence = {"schema": 1, "kind": DIVERGENCE_KIND,
                "shared_history": {**left_history, "changes": left_history["changes"][:common - 1]},
                "left_change": left_history["changes"][common - 1],
                "right_change": right_history["changes"][common - 1]}
    detail = _describe_divergence(shared, left[common], right[common])
    return {**verdict, **detail, "relationship": "diverged", "evidence_sha256": digest(evidence)}, evidence


def verify_policy_divergence(evidence, trusted_initial):
    """Check two signed successors of one authenticated predecessor from the initial rule."""
    fields(evidence, "schema kind shared_history left_change right_change", "reviewer policy divergence")
    integer(evidence["schema"], "divergence evidence schema", 1, 1)
    if evidence["kind"] != DIVERGENCE_KIND:
        raise LabError("Expected EduCreditLab reviewer policy divergence evidence")
    shared = _verified_history(evidence["shared_history"], trusted_initial)[-1]
    left = _verified_change(shared, evidence["left_change"])
    right = _verified_change(shared, evidence["right_change"])
    return {**_describe_divergence(shared, left, right), "policy_divergence_verified": True,
            "initial_policy_sha256": trusted_initial, "evidence_sha256": digest(evidence)}
