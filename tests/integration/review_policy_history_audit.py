"""Reproduce reviewer rule succession and review rechecks on synthetic evidence."""

import argparse
import json
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.keys import public_key
from educreditlab.model import LabError, digest, read_json, write_bytes, write_json
from educreditlab.policy_history import (append_policy_change, approve_policy_change, init_policy_history,
                                        verify_policy_history, verify_review_at_revision)
from educreditlab.review_attestation import attest_review, reviewer_fingerprint
from educreditlab.review_quorum import bundle_quorum, make_quorum_policy
from educreditlab.transport import decode_proof, gzip_proof


def expect_rejection(operation, message):
    try:
        operation()
    except LabError as error:
        if message in str(error):
            return
        raise
    raise AssertionError(f"Expected a refusal containing {message!r}")


def measure(proof_path, baseline, repeats, output):
    proof_data = proof_path.read_bytes()
    evidence = decode_proof(proof_data)
    assert digest(evidence) == baseline["proof_sha256"]
    manifest, checkpoint, plan = (baseline[name] for name in
                                  ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
    keys = [Ed25519PrivateKey.generate() for _ in range(5)]
    fingerprints = [reviewer_fingerprint(public_key(key)) for key in keys]
    initial = make_quorum_policy(plan, fingerprints[:4], 3)
    rotated = make_quorum_policy(plan, fingerprints[1:], 3)
    current = make_quorum_policy(plan, fingerprints[1:], 2)
    root = digest(initial)
    started = init_policy_history(initial, root)

    def extend(document, tip, policy, signers):
        approvals = [approve_policy_change(document, policy, keys[index], root, tip) for index in signers]
        return append_policy_change(document, policy, approvals, root, tip)

    expect_rejection(lambda: extend(started, root, rotated, (0, 1, 2)), "Successor policy signature threshold")
    expect_rejection(lambda: extend(started, root, rotated, (1, 2, 4)), "Preceding policy signature threshold")
    intermediate, intermediate_pin = extend(started, root, rotated, (0, 1, 2, 4))
    history, tip = extend(intermediate, intermediate_pin, current, (1, 2, 4))
    expect_rejection(lambda: verify_policy_history(intermediate, root, tip), "expected latest revision")

    def joint(policy, indices):
        statements = [attest_review(evidence, keys[index], manifest, checkpoint, plan) for index in indices]
        return bundle_quorum(policy, statements, digest(policy))

    previous_quorum = joint(initial, (0, 1, 2))
    current_quorum = joint(current, (1, 4))
    historical = verify_review_at_revision(history, previous_quorum, root, tip, revision=1)
    expect_rejection(lambda: verify_review_at_revision(history, previous_quorum, root, tip),
                     "Reviewer policy does not match")
    history_bytes = gzip_proof(history)
    current_bytes = gzip_proof(current_quorum)

    def verify_history():
        return verify_policy_history(decode_proof(history_bytes), root, tip)

    def verify_signatures():
        return verify_review_at_revision(decode_proof(history_bytes), decode_proof(current_bytes), root, tip)

    def recheck_evidence():
        return verify_review_at_revision(decode_proof(history_bytes), decode_proof(current_bytes), root, tip,
                                         trusted_manifest=manifest, trusted_checkpoint=checkpoint,
                                         expected_proof=baseline["proof_sha256"], proof=decode_proof(proof_data))

    history_result, history_time = time_trials(verify_history, repeats)
    signed, signed_time = time_trials(verify_signatures, repeats)
    checked, checked_time = time_trials(recheck_evidence, repeats)
    assert history_result["policy_history_verified"] and history_result["latest_revision"] == 3
    assert signed["quorum_verified"] and not signed["proof_rechecked"] and checked["proof_rechecked"]
    assert (signed["signer_count"], signed["threshold"], signed["policy_revision"]) == (2, 2, 3)
    assert (historical["signer_count"], historical["threshold"], historical["policy_revision"]) == (3, 3, 1)
    shared = ("receipt_count", "replay_count", "anchor_count", "checkpoint_height", "review_plan_sha256",
              "proof_sha256", "result_sha256")
    assert all(historical[name] == signed[name] == checked[name] == baseline[name] for name in shared)

    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "history.json.gz", history_bytes)
    write_bytes(output / "historical-quorum.json.gz", gzip_proof(previous_quorum))
    write_bytes(output / "current-quorum.json.gz", current_bytes)
    public_pins = {name: baseline[name] for name in
                   ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256", "proof_sha256", "result_sha256")}
    write_json(output / "pins.json", {**public_pins, "initial_policy_sha256": root, "latest_revision_sha256": tip})
    return {**{name: checked[name] for name in shared},
            "verified_revisions": 3, "verified_changes": 2,
            "thresholds": [3, 3, 2], "roster_sizes": [4, 4, 4], "change_signer_counts": [4, 3],
            "history_gzip_bytes": len(history_bytes), "current_quorum_gzip_bytes": len(current_bytes),
            "history_only": history_time, "current_signatures": signed_time, "with_evidence": checked_time,
            "current_policy_sha256": history_result["current_policy_sha256"],
            "independent_result_match": True, "historical_match": True,
            "old_record_rejected_under_current_rule": True, "truncated_history_rejected": True,
            "both_thresholds_required": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Result directory containing the packaged synthetic proofs")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, out = Path(args.source), Path(args.out_dir)
    benchmarks = json.loads((source / "review-quorum/measurement.json").read_text(encoding="utf-8"))["cases"]
    cases = []
    for label, proof, benchmark in zip(("three", "128"), ("demo/review.json.gz", "review-128.json.gz"),
                                       benchmarks, strict=True):
        pins = read_json(source / "review-quorum" / label / "pins.json")
        cases.append(measure(source / "review-plan" / proof, {**benchmark, **pins}, args.repeats, out / label))
    write_json(out / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                          "python": platform.python_version(), "cases": cases})
    for case in cases:
        print(f'{case["receipt_count"]} receipts, {case["verified_revisions"]} verified revisions, '
              f'{case["history_gzip_bytes"]} history bytes, {case["history_only"]["median_ms"]:.3f} ms history, '
              f'{case["current_signatures"]["median_ms"]:.3f} ms with signatures, '
              f'{case["with_evidence"]["median_ms"]:.3f} ms with evidence', flush=True)


if __name__ == "__main__":
    main()
