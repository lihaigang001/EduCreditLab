"""Sign a completed review and verify its shareable summary."""

from datetime import datetime, timezone
from hashlib import sha256

from .keys import public_key, sign, verify
from .lab import verify_review
from .model import LabError, digest, fields, hex_digest, integer

ATTESTATION_KIND = "educreditlab-review-attestation"
SIGNING_DOMAIN = "review-attestation"
REVISION_SIGNING_DOMAIN = "review-attestation-revision"
REVIEW_FIELDS = ("manifest_sha256", "checkpoint_sha256", "checkpoint_height", "review_plan_sha256",
                 "receipt_count", "replay_count", "anchor_count")
BODY_FIELDS = ("schema kind issued_at reviewer_public_key proof_sha256 result_sha256 " + " ".join(REVIEW_FIELDS))


def reviewer_fingerprint(public_hex):
    key = hex_digest(public_hex, "reviewer public key")
    return sha256(bytes.fromhex(key)).hexdigest()


def _verify_planned_review(proof, trusted_manifest, trusted_checkpoint, trusted_plan):
    if not isinstance(proof, dict) or type(proof.get("schema")) is not int or proof["schema"] != 4:
        raise LabError("A review attestation requires a plan-bound proof")
    return verify_review(proof, trusted_manifest, trusted_checkpoint=trusted_checkpoint, trusted_plan=trusted_plan)


def _committed_result(checked):
    return {**{key: checked[key] for key in REVIEW_FIELDS}, "result_sha256": digest(checked)}


def attest_review(proof, key, trusted_manifest, trusted_checkpoint, trusted_plan, *, policy_revision_sha256=None):
    binding = {}
    if policy_revision_sha256 is not None:
        binding["policy_revision_sha256"] = hex_digest(policy_revision_sha256, "reviewer policy revision fingerprint")
    checked = _verify_planned_review(proof, trusted_manifest, trusted_checkpoint, trusted_plan)
    body = {
        "schema": 2 if binding else 1, "kind": ATTESTATION_KIND,
        "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "reviewer_public_key": public_key(key),
        "proof_sha256": digest(proof),
        **binding,
        **_committed_result(checked),
    }
    domain = REVISION_SIGNING_DOMAIN if binding else SIGNING_DOMAIN
    return {"body": body, "signature": sign(key, domain, body)}


def _check_issued_at(value):
    try:
        timestamp = datetime.fromisoformat(value)
        if timestamp.tzinfo is not None:
            normalized = timestamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            if normalized == value:
                return
    except (ValueError, TypeError, OverflowError, OSError):
        pass
    raise LabError("Attestation issue time must be a UTC timestamp at second precision")


def _recheck_signed_result(body, proof, trusted_manifest, trusted_checkpoint, trusted_plan):
    """Recheck the evidence for an already authenticated review statement."""
    if trusted_manifest is None or trusted_checkpoint is None:
        raise LabError("Independent manifest and checkpoint fingerprints are required to recheck the proof")
    if digest(proof) != body["proof_sha256"]:
        raise LabError("Supplied proof does not match the attested proof fingerprint")
    checked = _verify_planned_review(proof, trusted_manifest, trusted_checkpoint, trusted_plan)
    if any(body[key] != value for key, value in _committed_result(checked).items()):
        raise LabError("Recomputed review result disagrees with the signed summary")


def verify_attestation(attestation, trusted_reviewer, trusted_plan, *, trusted_manifest=None,
                       trusted_checkpoint=None, expected_proof=None, proof=None, policy_revision_sha256=None):
    fields(attestation, "body signature", "review attestation")
    bound = policy_revision_sha256 is not None
    schema = 2 if bound else 1
    expected_fields = BODY_FIELDS + " policy_revision_sha256" if bound else BODY_FIELDS
    body = fields(attestation["body"], expected_fields, "signed review summary")
    integer(body["schema"], "attestation schema", schema, schema)
    if body["kind"] != ATTESTATION_KIND:
        raise LabError("Expected an EduCreditLab review attestation")
    if bound and body["policy_revision_sha256"] != hex_digest(policy_revision_sha256, "expected policy revision"):
        raise LabError("Signed review does not match the selected reviewer policy revision")
    _check_issued_at(body["issued_at"])
    height = integer(body["checkpoint_height"], "checkpoint height", 1)
    count = integer(body["receipt_count"], "receipt count", 1, height)
    replays = integer(body["replay_count"], "replay count", 0, count)
    integer(body["anchor_count"], "anchor count", count - replays, count - replays)
    for key in ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256", "proof_sha256", "result_sha256"):
        hex_digest(body[key], key)
    fingerprint = reviewer_fingerprint(body["reviewer_public_key"])
    if fingerprint != hex_digest(trusted_reviewer, "trusted reviewer key fingerprint"):
        raise LabError("Reviewer key does not match the independently trusted fingerprint")
    pins = {
        "review_plan_sha256": hex_digest(trusted_plan, "trusted review plan fingerprint"),
        "manifest_sha256": trusted_manifest,
        "checkpoint_sha256": trusted_checkpoint,
        "proof_sha256": expected_proof,
    }
    for name, pin in pins.items():
        if pin is not None and body[name] != hex_digest(pin, name):
            raise LabError(f"Attestation {name} does not match the expected fingerprint")
    domain = REVISION_SIGNING_DOMAIN if bound else SIGNING_DOMAIN
    verify(body["reviewer_public_key"], domain, body, attestation["signature"])
    if proof is not None:
        _recheck_signed_result(body, proof, trusted_manifest, trusted_checkpoint, trusted_plan)
    return {**body, "review_attestation": True, "signature_verified": True, "proof_rechecked": proof is not None,
            "reviewer_sha256": fingerprint}
