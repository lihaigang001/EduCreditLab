"""Compare legacy and revision-bound confirmations on constant review evidence."""

import argparse
import json
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.keys import public_key
from educreditlab.model import LabError, digest, read_json, write_bytes, write_json
from educreditlab.policy_history import (append_policy_change, approve_policy_change, attest_review_at_revision,
                                        bundle_review_at_revision, init_policy_history, verify_review_at_revision)
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


def measure(proof_path, pins, baseline, repeats, output):
    proof_bytes = proof_path.read_bytes()
    proof = decode_proof(proof_bytes)
    assert digest(proof) == pins["proof_sha256"] == baseline["proof_sha256"]
    manifest, checkpoint, plan = (pins[name] for name in
                                  ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
    keys = [Ed25519PrivateKey.generate() for _ in range(5)]
    fingerprints = [reviewer_fingerprint(public_key(key)) for key in keys]
    initial = make_quorum_policy(plan, fingerprints[:4], 3)
    intermediate = make_quorum_policy(plan, fingerprints[1:], 2)
    root = digest(initial)
    started = init_policy_history(initial, root)

    def advance(history, previous, next_policy, indices):
        approvals = [approve_policy_change(history, next_policy, keys[i], root, previous) for i in indices]
        return append_policy_change(history, next_policy, approvals, root, previous)

    def sign_bound(history, revision):
        return [attest_review_at_revision(history, proof, key, root, revision,
                                          trusted_manifest=manifest, trusted_checkpoint=checkpoint) for key in keys[:3]]

    earlier_statements = sign_bound(started, root)
    middle, middle_pin = advance(started, root, intermediate, (0, 1, 2, 4))
    history, latest = advance(middle, middle_pin, initial, (0, 1, 2))
    current_statements = sign_bound(history, latest)
    earlier = bundle_review_at_revision(history, earlier_statements, root, latest, revision=1)
    current = bundle_review_at_revision(history, current_statements, root, latest)
    legacy = bundle_quorum(initial, [attest_review(proof, key, manifest, checkpoint, plan) for key in keys[:3]], root)
    assert earlier["policy"] == current["policy"] == initial and root != latest
    historical = verify_review_at_revision(history, earlier, root, latest, revision=1, require_revision_binding=True)
    assert historical["revision_binding_verified"] and historical["policy_revision"] == 1
    expect_rejection(lambda: verify_review_at_revision(history, earlier, root, latest),
                     "selected reviewer policy revision")
    expect_rejection(lambda: verify_review_at_revision(history, current, root, latest, revision=1),
                     "selected reviewer policy revision")
    expect_rejection(lambda: verify_review_at_revision(history, legacy, root, latest, require_revision_binding=True),
                     "requires signatures that bind")
    history_bytes = gzip_proof(history)
    legacy_bytes, current_bytes = gzip_proof(legacy), gzip_proof(current)

    def verify_legacy():
        return verify_review_at_revision(decode_proof(history_bytes), decode_proof(legacy_bytes), root, latest)

    def verify_bound():
        return verify_review_at_revision(decode_proof(history_bytes), decode_proof(current_bytes), root, latest,
                                         require_revision_binding=True)

    def recheck_bound():
        return verify_review_at_revision(decode_proof(history_bytes), decode_proof(current_bytes), root, latest,
                                         require_revision_binding=True, proof=decode_proof(proof_bytes),
                                         trusted_manifest=manifest, trusted_checkpoint=checkpoint)

    compared, legacy_time = time_trials(verify_legacy, repeats)
    confirmed, bound_time = time_trials(verify_bound, repeats)
    rechecked, recheck_time = time_trials(recheck_bound, repeats)
    assert not compared["revision_binding_verified"] and confirmed["revision_binding_verified"]
    assert not confirmed["proof_rechecked"] and rechecked["proof_rechecked"]
    assert confirmed["policy_revision"] == 3 and confirmed["signer_count"] == 3
    evidence_fields = ("receipt_count", "replay_count", "anchor_count", "checkpoint_height", "review_plan_sha256",
                       "proof_sha256", "result_sha256")
    assert all(historical[k] == compared[k] == confirmed[k] == rechecked[k] == baseline[k] for k in evidence_fields)
    assert historical["reviewers"] == compared["reviewers"] == confirmed["reviewers"]

    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "history.json.gz", history_bytes)
    write_bytes(output / "historical-quorum.json.gz", gzip_proof(earlier))
    write_bytes(output / "current-quorum.json.gz", current_bytes)
    write_bytes(output / "legacy-quorum.json.gz", legacy_bytes)
    write_json(output / "pins.json", {**pins, "initial_policy_sha256": root, "latest_revision_sha256": latest})
    return {**{name: rechecked[name] for name in evidence_fields},
            "latest_revision": 3, "historical_revision": 1, "signer_count": confirmed["signer_count"],
            "history_gzip_bytes": len(history_bytes), "legacy_gzip_bytes": len(legacy_bytes),
            "bound_gzip_bytes": len(current_bytes), "legacy_signatures": legacy_time,
            "bound_signatures": bound_time, "bound_with_evidence": recheck_time,
            "identical_policy_content": True, "cross_revision_rejected": True,
            "legacy_rejected_in_strict_mode": True, "independent_result_match": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Result directory containing the packaged synthetic proofs")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, out = Path(args.source), Path(args.out_dir)
    baseline = json.loads((source / "review-policy-history/measurement.json").read_text(encoding="utf-8"))["cases"]
    cases = []
    for tag, proof, comparison in zip(("three", "128"), ("demo/review.json.gz", "review-128.json.gz"),
                                      baseline, strict=True):
        previous_pins = read_json(source / "review-policy-history" / tag / "pins.json")
        pins = {name: previous_pins[name] for name in
                ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256", "proof_sha256", "result_sha256")}
        cases.append(measure(source / "review-plan" / proof, pins, comparison, args.repeats, out / tag))
    write_json(out / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                          "python": platform.python_version(), "cases": cases})
    for case in cases:
        print(f'{case["receipt_count"]} receipts, legacy/bound packet sizes '
              f'{case["legacy_gzip_bytes"]}/{case["bound_gzip_bytes"]} bytes, '
              f'{case["bound_signatures"]["median_ms"]:.3f} ms verifying signed revisions, '
              f'{case["bound_with_evidence"]["median_ms"]:.3f} ms with evidence review', flush=True)


if __name__ == "__main__":
    main()
