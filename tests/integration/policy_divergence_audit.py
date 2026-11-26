"""Measure verification of complete policy histories and portable divergence evidence."""

import argparse
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.keys import public_key
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.policy_divergence import compare_policy_histories, verify_policy_divergence
from educreditlab.policy_history import (append_policy_change, approve_policy_change, attest_review_at_revision,
                                        bundle_review_at_revision, init_policy_history, verify_review_at_revision)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.review_quorum import make_quorum_policy
from educreditlab.transport import decode_proof, gzip_proof, read_proof
from revision_review_audit import expect_rejection


def measure(left_history, right_history, left_pin, right_pin, initial_pin, repeats, output):
    left_bytes, right_bytes = gzip_proof(left_history), gzip_proof(right_history)

    def compare():
        return compare_policy_histories(decode_proof(left_bytes), decode_proof(right_bytes),
                                        initial_pin, left_pin, right_pin)

    (result, evidence), compare_time = time_trials(compare, repeats)
    assert (result["relationship"], result["shared_revision"], result["divergent_revision"]) == ("diverged", 2, 3)
    payload = gzip_proof(evidence)
    verified, evidence_time = time_trials(lambda: verify_policy_divergence(decode_proof(payload), initial_pin), repeats)
    assert verified["policy_divergence_verified"] and verified["evidence_sha256"] == result["evidence_sha256"]
    assert len(verified["shared_predecessor_approvers"]) == 3
    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "left.json.gz", left_bytes)
    write_bytes(output / "right.json.gz", right_bytes)
    write_json(output / "pins.json", {
        key: result[key] for key in ("initial_policy_sha256", "left_latest_revision_sha256",
                                     "right_latest_revision_sha256", "evidence_sha256")
    })
    stats = {**result, "history_pair_gzip_bytes": len(left_bytes) + len(right_bytes),
             "evidence_gzip_bytes": len(payload), "compare_histories": compare_time, "verify_evidence": evidence_time}
    return stats, payload


def experiment(source, output, repeats):
    pins = read_json(source / "revision-bound-review/128/pins.json")
    proof = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(proof) == pins["proof_sha256"]
    manifest, checkpoint, plan = (pins[k] for k in ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
    keys = [Ed25519PrivateKey.generate() for _ in range(4)]
    roster = [reviewer_fingerprint(public_key(key)) for key in keys]
    policies = {threshold: make_quorum_policy(plan, roster, threshold) for threshold in (2, 3, 4)}
    initial_pin = digest(policies[2])
    started = init_policy_history(policies[2], initial_pin)

    def advance(history, pin, threshold, signers):
        policy = policies[threshold]
        approvals = [approve_policy_change(history, policy, key, initial_pin, pin) for key in signers]
        return append_policy_change(history, policy, approvals, initial_pin, pin)

    shared, shared_pin = advance(started, initial_pin, 3, keys[:3])
    left, left_pin = advance(shared, shared_pin, 2, keys[:3])
    right, right_pin = advance(shared, shared_pin, 4, keys)
    short, short_payload = measure(left, right, left_pin, right_pin, initial_pin, repeats, output / "short")
    for threshold in (3, 2) * 11 + (3, 4):
        left, left_pin = advance(left, left_pin, threshold, keys)
        right, right_pin = advance(right, right_pin, threshold, keys)
    longer, long_payload = measure(left, right, left_pin, right_pin, initial_pin, repeats, output / "long")
    assert short_payload == long_payload
    assert longer["left_latest_revision"] == longer["right_latest_revision"] == 27
    assert left["changes"][-1]["body"]["policy"] == right["changes"][-1]["body"]["policy"] == policies[4]
    assert left_pin != right_pin

    def review(history, pin):
        statements = [attest_review_at_revision(history, proof, key, initial_pin, pin,
                                               trusted_manifest=manifest, trusted_checkpoint=checkpoint)
                      for key in keys]
        joint = bundle_review_at_revision(history, statements, initial_pin, pin)
        verified = verify_review_at_revision(history, joint, initial_pin, pin, require_revision_binding=True,
                                            trusted_manifest=manifest, trusted_checkpoint=checkpoint, proof=proof)
        assert verified["revision_binding_verified"] and verified["proof_rechecked"]
        assert verified["result_sha256"] == pins["result_sha256"]
        assert (verified["receipt_count"], verified["replay_count"], verified["anchor_count"]) == (128, 16, 112)
        return joint, verified

    left_joint, checked = review(left, left_pin)
    right_joint, also_checked = review(right, right_pin)
    expect_rejection(lambda: verify_review_at_revision(right, left_joint, initial_pin, right_pin,
                                                       require_revision_binding=True),
                     "selected reviewer policy revision")
    expect_rejection(lambda: verify_review_at_revision(left, right_joint, initial_pin, left_pin,
                                                       require_revision_binding=True),
                     "selected reviewer policy revision")
    assert checked["policy_sha256"] == also_checked["policy_sha256"] == digest(policies[4])
    write_bytes(output / "divergence.json.gz", short_payload)
    write_bytes(output / "long/left-quorum.json.gz", gzip_proof(left_joint))
    write_bytes(output / "long/right-quorum.json.gz", gzip_proof(right_joint))
    evidence_fields = ("receipt_count", "replay_count", "anchor_count", "checkpoint_height", "review_plan_sha256",
                       "manifest_sha256", "checkpoint_sha256", "proof_sha256", "result_sha256")
    return {"cases": [short, longer], "review": {key: checked[key] for key in evidence_fields},
            "same_exhibit_for_both_lengths": True, "same_long_tip_policy_content": True,
            "cross_branch_confirmations_rejected": True, "independent_replay_matches": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Result directory with the packaged synthetic proof")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    output = Path(args.out_dir)
    result = experiment(Path(args.source), output, args.repeats)
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                          "python": platform.python_version(), **result})
    for case in result["cases"]:
        print(f'{case["left_latest_revision"]} revisions per branch, '
              f'{case["history_pair_gzip_bytes"]} bytes for the pair, {case["evidence_gzip_bytes"]} evidence bytes, '
              f'{case["compare_histories"]["median_ms"]:.3f} ms comparing histories, '
              f'{case["verify_evidence"]["median_ms"]:.3f} ms verifying evidence', flush=True)


if __name__ == "__main__":
    main()
