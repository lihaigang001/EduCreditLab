"""Measure pinned institutional decisions and verification of the selected review."""

import argparse
import json
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.keys import public_key
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.policy_history import verify_policy_history
from educreditlab.policy_resolution import (bundle_policy_resolution, make_resolution_authority,
                                             sign_policy_resolution, verify_policy_resolution, verify_resolved_review)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def make_packet(profile, evidence, history, keys, authority, selected):
    approvals = [sign_policy_resolution(profile, evidence, history, key, authority, selected) for key in keys]
    return bundle_policy_resolution(profile, evidence, history, approvals, authority, selected)


def measure(input_case, output_case, profile, evidence, keys, authority, repeats):
    pins = read_json(input_case / "pins.json")
    history_bytes = (input_case / "left.json.gz").read_bytes()
    initial, selected = (pins[name] for name in ("initial_policy_sha256", "left_latest_revision_sha256"))
    assert digest(evidence) == pins["evidence_sha256"]
    packet = make_packet(profile, evidence, decode_proof(history_bytes), keys, authority, selected)
    decision = digest(packet["decision"])
    packet_bytes = gzip_proof(packet)
    history, history_time = time_trials(
        lambda: verify_policy_history(decode_proof(history_bytes), initial, selected), repeats)
    checked, decision_time = time_trials(
        lambda: verify_policy_resolution(decode_proof(packet_bytes), authority, decision), repeats)
    assert checked["policy_resolution_verified"] and checked["selected_revision"] == history["latest_revision"]
    assert checked["selected_revision_sha256"] == history["latest_revision_sha256"] == selected
    assert checked["resolution_signer_count"] == checked["resolution_threshold"] == 2
    output_case.mkdir(parents=True, exist_ok=True)
    write_bytes(output_case / "resolution.json.gz", packet_bytes)
    return {**checked, "history_gzip_bytes": len(history_bytes), "resolution_gzip_bytes": len(packet_bytes),
            "verify_history": history_time, "verify_resolution": decision_time}, packet_bytes


def experiment(source, output, repeats):
    previous = source / "policy-divergence"
    evidence = read_proof(previous / "divergence.json.gz")
    long_pins = read_json(previous / "long/pins.json")
    initial = long_pins["initial_policy_sha256"]
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    profile = make_resolution_authority(initial, [reviewer_fingerprint(public_key(key)) for key in keys], 2)
    authority = digest(profile)
    short, _ = measure(previous / "short", output / "short", profile, evidence, keys[:2], authority, repeats)
    long, packet_bytes = measure(previous / "long", output / "long", profile, evidence, keys[:2], authority, repeats)
    assert (short["selected_revision"], long["selected_revision"]) == (3, 27)
    assert short["selected_successor_sha256"] == long["selected_successor_sha256"]
    assert short["decision_sha256"] != long["decision_sha256"]
    alternate_tip = long_pins["right_latest_revision_sha256"]
    alternate = make_packet(profile, evidence, read_proof(previous / "long/right.json.gz"),
                            keys[:2], authority, alternate_tip)
    alternate_decision = digest(alternate["decision"])
    assert verify_policy_resolution(alternate, authority, alternate_decision)["selected_revision_sha256"] == alternate_tip
    expect_rejection(lambda: verify_policy_resolution(alternate, authority, long["decision_sha256"]),
                     "independently expected decision")

    previous_measurement = json.loads((previous / "measurement.json").read_text(encoding="utf-8"))["review"]
    proof_data = (source / "review-plan/review-128.json.gz").read_bytes()
    assert digest(decode_proof(proof_data)) == previous_measurement["proof_sha256"]
    selected_bytes = (previous / "long/left-quorum.json.gz").read_bytes()
    other = read_proof(previous / "long/right-quorum.json.gz")
    assert decode_proof(selected_bytes)["policy"] == other["policy"]

    def verify_review(recheck=False):
        inputs = {}
        if recheck:
            inputs = {"proof": decode_proof(proof_data), "trusted_manifest": previous_measurement["manifest_sha256"],
                      "trusted_checkpoint": previous_measurement["checkpoint_sha256"]}
        return verify_resolved_review(decode_proof(packet_bytes), decode_proof(selected_bytes),
                                      authority, long["decision_sha256"], **inputs)

    approved, review_time = time_trials(verify_review, repeats)
    checked, evidence_time = time_trials(lambda: verify_review(recheck=True), repeats)
    assert approved["revision_binding_verified"] and checked["proof_rechecked"]
    assert checked["policy_revision_sha256"] == long["selected_revision_sha256"]
    expect_rejection(lambda: verify_resolved_review(decode_proof(packet_bytes), other, authority,
                                                    long["decision_sha256"]),
                     "selected reviewer policy revision")
    review_fields = ("receipt_count", "replay_count", "anchor_count", "checkpoint_height", "review_plan_sha256",
                     "manifest_sha256", "checkpoint_sha256", "proof_sha256", "result_sha256")
    assert (checked["receipt_count"], checked["replay_count"], checked["anchor_count"]) == (128, 16, 112)
    assert all(checked[field] == approved[field] == previous_measurement[field] for field in review_fields)
    write_bytes(output / "long/alternate-resolution.json.gz", gzip_proof(alternate))
    for label, case in (("short", short), ("long", long)):
        pins = {key: case[key] for key in ("authority_sha256", "decision_sha256", "selected_revision_sha256")}
        if label == "long":
            pins["alternate_decision_sha256"] = alternate_decision
        write_json(output / label / "pins.json", pins)
    return {"cases": [short, long], "authority_roster_size": len(keys), "authority_threshold": 2,
            "review": {**{field: checked[field] for field in review_fields},
                       "verify_review": review_time, "with_evidence": evidence_time},
            "alternative_decision_rejected_under_selection_pin": True,
            "other_branch_confirmation_rejected": True, "selected_result_independently_replayed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Result directory with packaged histories and proof")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    output = Path(args.out_dir)
    measured = experiment(Path(args.source), output, args.repeats)
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                               "python": platform.python_version(), **measured})
    for case in measured["cases"]:
        print(f'Selected revision {case["selected_revision"]}, {case["resolution_gzip_bytes"]} bytes, '
              f'{case["verify_resolution"]["median_ms"]:.3f} ms to verify resolution', flush=True)
    review = measured["review"]
    print(f'{review["receipt_count"]} receipts: {review["verify_review"]["median_ms"]:.3f} ms including review, '
          f'{review["with_evidence"]["median_ms"]:.3f} ms including evidence recheck', flush=True)


if __name__ == "__main__":
    main()
