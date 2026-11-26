"""Authorize successive reviewer policies and select the rules for a review."""

from .keys import public_key, sign, verify
from .model import LabError, digest, fields, hex_digest, integer, sequence
from .review_attestation import attest_review, reviewer_fingerprint
from .review_quorum import _validate_policy, bundle_quorum, verify_quorum

HISTORY_KIND = "educreditlab-review-policy-history"
CHANGE_KIND = "educreditlab-review-policy-change"
CHANGE_DOMAIN = "review-policy-change"
MAX_REVISIONS = 1_000_000


def init_policy_history(policy, trusted_initial):
    _validate_policy(policy, trusted_initial)
    return {"schema": 1, "kind": HISTORY_KIND, "initial_policy": policy, "changes": []}


def _change_body(previous, next_policy):
    _validate_policy(next_policy, digest(next_policy))
    if next_policy["review_plan_sha256"] != previous["policy"]["review_plan_sha256"]:
        raise LabError("A policy change must keep the independently agreed review plan")
    revision = integer(previous["revision"] + 1, "policy change revision", 2, MAX_REVISIONS)
    return {"schema": 1, "kind": CHANGE_KIND, "revision": revision,
            "previous_revision_sha256": previous["revision_sha256"], "policy": next_policy}


def _approval_signer(approval):
    fields(approval, "reviewer_public_key signature", "policy change approval")
    return reviewer_fingerprint(approval["reviewer_public_key"])


def _verify_approvals(previous, body, approvals):
    before = previous["policy"]
    after = body["policy"]
    old_keys, new_keys = set(before["reviewer_sha256"]), set(after["reviewer_sha256"])
    allowed = old_keys | new_keys
    sequence(approvals, "policy change approvals", 0, len(allowed))
    signers = []
    for approval in approvals:
        signer = _approval_signer(approval)
        if signer not in allowed:
            raise LabError("A policy change approval uses a key outside both rosters")
        if signers and signer <= signers[-1]:
            raise LabError("Policy change approvals require distinct keys in fingerprint order")
        verify(approval["reviewer_public_key"], CHANGE_DOMAIN, body, approval["signature"])
        signers.append(signer)
    if len(old_keys.intersection(signers)) < before["threshold"]:
        raise LabError("Preceding policy signature threshold has not been met")
    if len(new_keys.intersection(signers)) < after["threshold"]:
        raise LabError("Successor policy signature threshold has not been met")
    return signers


def _verified_change(prior, change):
    fields(change, "body approvals", "signed policy change")
    body = fields(change["body"], "schema kind revision previous_revision_sha256 policy", "policy change body")
    integer(body["schema"], "policy change schema", 1, 1)
    integer(body["revision"], "policy change revision", prior["revision"] + 1, prior["revision"] + 1)
    if body != _change_body(prior, body["policy"]):
        raise LabError("Policy change does not match the preceding revision")
    signers = _verify_approvals(prior, body, change["approvals"])
    return {"revision": body["revision"], "revision_sha256": digest(body), "policy": body["policy"],
            "approver_sha256": signers}


def _verified_history(history, trusted_initial):
    fields(history, "schema kind initial_policy changes", "reviewer policy history")
    integer(history["schema"], "policy history schema", 1, 1)
    if history["kind"] != HISTORY_KIND:
        raise LabError("Expected an EduCreditLab reviewer policy history")
    initial = history["initial_policy"]
    _validate_policy(initial, trusted_initial)
    revisions = [{"revision": 1, "revision_sha256": trusted_initial, "policy": initial}]
    for change in sequence(history["changes"], "policy history changes", 0, MAX_REVISIONS - 1):
        revisions.append(_verified_change(revisions[-1], change))
    return revisions


def _verified_revisions(history, trusted_initial, trusted_revision):
    expected = hex_digest(trusted_revision, "independently expected latest revision fingerprint")
    revisions = _verified_history(history, trusted_initial)
    if revisions[-1]["revision_sha256"] != expected:
        raise LabError("Policy history does not match the expected latest revision")
    return revisions


def verify_policy_history(history, trusted_initial, trusted_revision):
    latest = _verified_revisions(history, trusted_initial, trusted_revision)[-1]
    policy = latest["policy"]
    return {"policy_history_verified": True, "initial_policy_sha256": trusted_initial,
            "latest_revision": latest["revision"], "latest_revision_sha256": latest["revision_sha256"],
            "current_policy_sha256": digest(policy), "threshold": policy["threshold"],
            "reviewer_count": len(policy["reviewer_sha256"])}


def approve_policy_change(history, next_policy, key, trusted_initial, trusted_revision):
    prior = _verified_revisions(history, trusted_initial, trusted_revision)[-1]
    body = _change_body(prior, next_policy)
    pub = public_key(key)
    signer = reviewer_fingerprint(pub)
    if signer not in prior["policy"]["reviewer_sha256"] and signer not in next_policy["reviewer_sha256"]:
        raise LabError("The signing key is outside both reviewer rosters")
    return {"reviewer_public_key": pub, "signature": sign(key, CHANGE_DOMAIN, body)}


def append_policy_change(history, next_policy, approvals, trusted_initial, trusted_revision):
    prior = _verified_revisions(history, trusted_initial, trusted_revision)[-1]
    body = _change_body(prior, next_policy)
    ordered = sorted(approvals, key=_approval_signer)
    _verify_approvals(prior, body, ordered)
    return {**history, "changes": [*history["changes"], {"body": body, "approvals": ordered}]}, digest(body)


def _select_revision(revisions, revision):
    if revision is None:
        return revisions[-1]
    return revisions[integer(revision, "selected policy revision", 1, len(revisions)) - 1]


def attest_review_at_revision(history, proof, key, trusted_initial, trusted_revision, *,
                              trusted_manifest, trusted_checkpoint):
    latest = _verified_revisions(history, trusted_initial, trusted_revision)[-1]
    policy = latest["policy"]
    if reviewer_fingerprint(public_key(key)) not in policy["reviewer_sha256"]:
        raise LabError("The signing key is outside the current reviewer roster")
    return attest_review(proof, key, trusted_manifest, trusted_checkpoint, policy["review_plan_sha256"],
                         policy_revision_sha256=latest["revision_sha256"])


def bundle_review_at_revision(history, attestations, trusted_initial, trusted_revision, *, revision=None):
    selected = _select_revision(_verified_revisions(history, trusted_initial, trusted_revision), revision)
    return bundle_quorum(selected["policy"], attestations, digest(selected["policy"]),
                         policy_revision_sha256=selected["revision_sha256"])


def verify_review_at_revision(history, bundle, trusted_initial, trusted_revision, *, revision=None,
                              trusted_manifest=None, trusted_checkpoint=None, expected_proof=None, proof=None,
                              require_revision_binding=False):
    revisions = _verified_revisions(history, trusted_initial, trusted_revision)
    return _verify_review_in_revisions(revisions, bundle, revision=revision, trusted_manifest=trusted_manifest,
                                       trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof,
                                       proof=proof, require_revision_binding=require_revision_binding)


def _verify_review_in_revisions(revisions, bundle, *, revision=None, trusted_manifest=None,
                                trusted_checkpoint=None, expected_proof=None, proof=None,
                                require_revision_binding=False):
    selected = _select_revision(revisions, revision)
    bound = isinstance(bundle, dict) and bundle.get("schema") == 2
    if require_revision_binding and not bound:
        raise LabError("This review requires signatures that bind the selected reviewer policy revision")
    result = verify_quorum(bundle, digest(selected["policy"]), trusted_manifest=trusted_manifest,
                           trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof, proof=proof,
                           policy_revision_sha256=selected["revision_sha256"] if bound else None)
    return {**result, "revision_binding_verified": bound,
            "policy_revision": selected["revision"], "policy_revision_sha256": selected["revision_sha256"],
            "latest_revision": len(revisions), "latest_revision_sha256": revisions[-1]["revision_sha256"]}
