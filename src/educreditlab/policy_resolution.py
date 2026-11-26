"""Verify an institutional choice of an exact reviewer rule revision after divergence."""

from .keys import public_key, sign, verify
from .model import LabError, digest, fields, hex_digest, integer, sequence
from .policy_divergence import verify_policy_divergence
from .policy_history import _verified_revisions, _verify_review_in_revisions
from .review_attestation import reviewer_fingerprint

AUTHORITY_KIND = "educreditlab-review-policy-resolution-authority"
DECISION_KIND = "educreditlab-review-policy-resolution-decision"
RESOLUTION_KIND = "educreditlab-review-policy-resolution"
RESOLUTION_DOMAIN = "review-policy-resolution"


def _validate_authority(profile, trusted_authority):
    fields(profile, "schema kind initial_policy_sha256 resolver_sha256 threshold", "resolution authority")
    integer(profile["schema"], "resolution authority schema", 1, 1)
    if profile["kind"] != AUTHORITY_KIND:
        raise LabError("Expected an EduCreditLab resolution authority")
    if digest(profile) != hex_digest(trusted_authority, "trusted resolution authority fingerprint"):
        raise LabError("Resolution authority does not match the independently trusted fingerprint")
    hex_digest(profile["initial_policy_sha256"], "initial reviewer policy fingerprint")
    roster = sequence(profile["resolver_sha256"], "resolution authority keys", 1, 1_000_000)
    if roster != sorted({hex_digest(key, "resolution authority key fingerprint") for key in roster}):
        raise LabError("Resolution authority requires distinct keys in fingerprint order")
    integer(profile["threshold"], "resolution signature threshold", 1, len(roster))


def make_resolution_authority(trusted_initial, resolvers, threshold):
    profile = {"schema": 1, "kind": AUTHORITY_KIND, "initial_policy_sha256": trusted_initial,
               "resolver_sha256": sorted(hex_digest(key, "resolution authority key fingerprint") for key in resolvers),
               "threshold": threshold}
    _validate_authority(profile, digest(profile))
    return profile


def _decision_context(profile, evidence, history, trusted_authority, selected_revision):
    _validate_authority(profile, trusted_authority)
    initial = profile["initial_policy_sha256"]
    divergence = verify_policy_divergence(evidence, initial)
    revisions = _verified_revisions(history, initial, selected_revision)
    split = divergence["divergent_revision"]
    if len(revisions) < split:
        raise LabError("The selected history ends before the demonstrated divergence")
    successor = revisions[split - 1]["revision_sha256"]
    if successor not in (divergence["left_successor_sha256"], divergence["right_successor_sha256"]):
        raise LabError("The selected history must descend from a demonstrated successor")
    body = {"schema": 1, "kind": DECISION_KIND, "authority_sha256": trusted_authority,
            "divergence_sha256": divergence["evidence_sha256"], "selected_successor_sha256": successor,
            "selected_revision_sha256": selected_revision}
    return body, revisions


def _approval_signer(approval):
    fields(approval, "resolver_public_key signature", "resolution approval")
    return reviewer_fingerprint(approval["resolver_public_key"])


def _verify_approvals(profile, body, approvals, *, domain=RESOLUTION_DOMAIN):
    roster = set(profile["resolver_sha256"])
    signers = []
    for approval in sequence(approvals, "resolution approvals", 0, len(roster)):
        signer = _approval_signer(approval)
        if signer not in roster:
            raise LabError("Resolution approval is outside the trusted authority roster")
        if signers and signer <= signers[-1]:
            raise LabError("Resolution approvals require distinct keys in fingerprint order")
        verify(approval["resolver_public_key"], domain, body, approval["signature"])
        signers.append(signer)
    if len(signers) < profile["threshold"]:
        raise LabError("Resolution signature threshold has not been met")
    return signers


def _sign_approval(profile, body, key, *, domain):
    pub = public_key(key)
    if reviewer_fingerprint(pub) not in profile["resolver_sha256"]:
        raise LabError("The signing key is outside the trusted resolution authority")
    return {"resolver_public_key": pub, "signature": sign(key, domain, body)}


def sign_policy_resolution(profile, evidence, history, key, trusted_authority, selected_revision):
    body, _ = _decision_context(profile, evidence, history, trusted_authority, selected_revision)
    return _sign_approval(profile, body, key, domain=RESOLUTION_DOMAIN)


def bundle_policy_resolution(profile, evidence, history, approvals, trusted_authority, selected_revision):
    body, _ = _decision_context(profile, evidence, history, trusted_authority, selected_revision)
    ordered = sorted(approvals, key=_approval_signer)
    _verify_approvals(profile, body, ordered)
    return {"schema": 1, "kind": RESOLUTION_KIND, "authority": profile, "divergence": evidence,
            "selected_history": history, "decision": body, "approvals": ordered}


def _verified_resolution(packet, trusted_authority, trusted_decision):
    fields(packet, "schema kind authority divergence selected_history decision approvals", "policy resolution packet")
    integer(packet["schema"], "policy resolution packet schema", 1, 1)
    if packet["kind"] != RESOLUTION_KIND:
        raise LabError("Expected an EduCreditLab policy resolution packet")
    decision = fields(packet["decision"],
                      "schema kind authority_sha256 divergence_sha256 selected_successor_sha256 selected_revision_sha256",
                      "policy resolution decision")
    integer(decision["schema"], "resolution decision schema", 1, 1)
    if digest(decision) != hex_digest(trusted_decision, "independently expected resolution decision fingerprint"):
        raise LabError("Resolution does not match the independently expected decision")
    profile = packet["authority"]
    body, revisions = _decision_context(profile, packet["divergence"], packet["selected_history"],
                                        trusted_authority, decision["selected_revision_sha256"])
    if decision != body:
        raise LabError("Signed resolution does not match the verified evidence and selected revision")
    signers = _verify_approvals(profile, decision, packet["approvals"])
    return ({"policy_resolution_verified": True, "decision_sha256": trusted_decision,
             "authority_sha256": trusted_authority, "initial_policy_sha256": profile["initial_policy_sha256"],
             "divergence_sha256": body["divergence_sha256"], "selected_successor_sha256": body["selected_successor_sha256"],
             "selected_revision": len(revisions), "selected_revision_sha256": body["selected_revision_sha256"],
             "resolution_threshold": profile["threshold"], "resolution_signer_count": len(signers)}, revisions)


def verify_policy_resolution(packet, trusted_authority, trusted_decision):
    result, _ = _verified_resolution(packet, trusted_authority, trusted_decision)
    return result


def verify_resolved_review(packet, bundle, trusted_authority, trusted_decision, *,
                           trusted_manifest=None, trusted_checkpoint=None, expected_proof=None, proof=None):
    resolution, revisions = _verified_resolution(packet, trusted_authority, trusted_decision)
    review = _verify_review_in_revisions(revisions, bundle, trusted_manifest=trusted_manifest,
                                         trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof,
                                         proof=proof, require_revision_binding=True)
    return {**resolution, **review}
