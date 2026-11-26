"""Collect independent reviewer signatures under one pinned review policy."""

from .model import LabError, digest, fields, hex_digest, integer, sequence
from .review_attestation import REVIEW_FIELDS, _recheck_signed_result, reviewer_fingerprint, verify_attestation

POLICY_KIND = "educreditlab-review-quorum-policy"
QUORUM_KIND = "educreditlab-review-quorum"
AGREEMENT_FIELDS = (*REVIEW_FIELDS, "proof_sha256", "result_sha256")


def _validate_policy(policy, trusted_policy):
    fields(policy, "schema kind review_plan_sha256 reviewer_sha256 threshold", "reviewer policy")
    integer(policy["schema"], "reviewer policy schema", 1, 1)
    if policy["kind"] != POLICY_KIND:
        raise LabError("Expected an EduCreditLab reviewer policy")
    if digest(policy) != hex_digest(trusted_policy, "trusted reviewer policy fingerprint"):
        raise LabError("Reviewer policy does not match the independently trusted fingerprint")
    hex_digest(policy["review_plan_sha256"], "review plan fingerprint")
    roster = sequence(policy["reviewer_sha256"], "reviewer fingerprints", 1, 1_000_000)
    keys = sorted({hex_digest(key, "reviewer key fingerprint") for key in roster})
    if keys != roster:
        raise LabError("Reviewer policy requires unique and sorted key fingerprints")
    integer(policy["threshold"], "reviewer signature threshold", 1, len(keys))
    return set(keys)


def make_quorum_policy(trusted_plan, reviewers, threshold):
    policy = {
        "schema": 1, "kind": POLICY_KIND,
        "review_plan_sha256": hex_digest(trusted_plan, "review plan fingerprint"),
        "reviewer_sha256": sorted(hex_digest(key, "reviewer key fingerprint") for key in reviewers),
        "threshold": threshold,
    }
    _validate_policy(policy, digest(policy))
    return policy


def _signer(attestation):
    fields(attestation, "body signature", "review attestation")
    body = attestation["body"]
    if not isinstance(body, dict):
        raise LabError("Expected a signed review summary")
    return reviewer_fingerprint(body.get("reviewer_public_key"))


def bundle_quorum(policy, attestations, trusted_policy, *, policy_revision_sha256=None):
    bundle = {"schema": 2 if policy_revision_sha256 is not None else 1, "kind": QUORUM_KIND, "policy": policy,
              "attestations": sorted(attestations, key=_signer)}
    verify_quorum(bundle, trusted_policy, policy_revision_sha256=policy_revision_sha256)
    return bundle


def verify_quorum(bundle, trusted_policy, *, trusted_manifest=None, trusted_checkpoint=None,
                  expected_proof=None, proof=None, policy_revision_sha256=None):
    fields(bundle, "schema kind policy attestations", "joint review attestation")
    schema = 2 if policy_revision_sha256 is not None else 1
    integer(bundle["schema"], "joint review attestation schema", schema, schema)
    if bundle["kind"] != QUORUM_KIND:
        raise LabError("Expected an EduCreditLab joint review attestation")
    policy = bundle["policy"]
    roster = _validate_policy(policy, trusted_policy)
    threshold = policy["threshold"]
    plan = policy["review_plan_sha256"]
    records = sequence(bundle["attestations"], "review attestations", 0, len(roster))
    if len(records) < threshold:
        raise LabError("The reviewer signature threshold has not been met")
    signers, agreement = [], None
    for record in records:
        signer = _signer(record)
        if signer not in roster:
            raise LabError("A reviewer key is outside the trusted policy")
        if signers and signer <= signers[-1]:
            raise LabError("Joint review requires distinct reviewers in fingerprint order")
        verified = verify_attestation(record, signer, plan, trusted_manifest=trusted_manifest,
                                      trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof,
                                      policy_revision_sha256=policy_revision_sha256)
        summary = {key: verified[key] for key in AGREEMENT_FIELDS}
        if agreement is None:
            agreement = summary
        elif agreement != summary:
            raise LabError("Reviewer statements disagree on the proof or review result")
        signers.append(signer)
    if proof is not None:
        _recheck_signed_result(agreement, proof, trusted_manifest, trusted_checkpoint, plan)
    return {**agreement, "quorum_verified": True, "proof_rechecked": proof is not None,
            "policy_sha256": trusted_policy, "threshold": threshold, "signer_count": len(signers),
            "reviewers": signers}
