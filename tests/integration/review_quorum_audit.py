"""Measure approval thresholds and evidence rechecks on the packaged synthetic proofs."""

import argparse
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.keys import public_key
from educreditlab.model import canonical, digest, read_json, write_bytes, write_json
from educreditlab.review_attestation import attest_review, reviewer_fingerprint
from educreditlab.review_quorum import bundle_quorum, make_quorum_policy, verify_quorum
from educreditlab.transport import decode_proof, gzip_proof


def measure(source, pins, roster_size, threshold, repeats, output):
    proof_data = source.read_bytes()
    proof = decode_proof(proof_data)
    assert digest(proof) == pins["proof_sha256"]
    manifest, checkpoint, plan = (pins[name] for name in ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
    keys = [Ed25519PrivateKey.generate() for _ in range(roster_size)]
    roster = [reviewer_fingerprint(public_key(key)) for key in keys]
    policy = make_quorum_policy(plan, roster, threshold)
    trusted_policy = digest(policy)
    statements = [attest_review(proof, key, manifest, checkpoint, plan) for key in keys[:threshold]]
    bundle = bundle_quorum(policy, statements, trusted_policy)
    payload = gzip_proof(bundle)

    def verify_signatures():
        return verify_quorum(decode_proof(payload), trusted_policy)

    def recheck():
        return verify_quorum(decode_proof(payload), trusted_policy, trusted_manifest=manifest,
                             trusted_checkpoint=checkpoint, proof=decode_proof(proof_data))

    signed, signature_time = time_trials(verify_signatures, repeats)
    checked, recheck_time = time_trials(recheck, repeats)
    assert signed["quorum_verified"] and not signed["proof_rechecked"] and checked["proof_rechecked"]
    assert signed["proof_sha256"] == checked["proof_sha256"] == pins["proof_sha256"]
    assert signed["result_sha256"] == checked["result_sha256"] == statements[0]["body"]["result_sha256"]
    assert signed["signer_count"] == signed["threshold"] == threshold
    assert all(name not in canonical(bundle) for name in (b'"evidence"', b'"transcript"', b'"decision"', b'"receipts"'))
    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "quorum.json.gz", payload)
    write_json(output / "policy.json", policy)
    public_pins = {name: pins[name] for name in
                   ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256", "proof_sha256")}
    write_json(output / "pins.json", {**public_pins, "policy_sha256": trusted_policy})
    fields = ("receipt_count", "replay_count", "anchor_count", "checkpoint_height", "signer_count",
              "threshold", "policy_sha256", "review_plan_sha256", "proof_sha256", "result_sha256")
    return {**{field: checked[field] for field in fields},
            "roster_size": roster_size, "quorum_gzip_bytes": len(payload), "proof_gzip_bytes": len(proof_data),
            "signatures_only": signature_time, "with_proof_recheck": recheck_time, "independent_result_match": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Result directory containing the packaged synthetic proofs")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    cases = [
        measure(source / "review-plan/demo/review.json.gz", read_json(source / "review-attestation/three/pins.json"),
                3, 2, args.repeats, output / "three"),
        measure(source / "review-plan/review-128.json.gz", read_json(source / "review-attestation/128/pins.json"),
                4, 3, args.repeats, output / "128"),
    ]
    write_json(output / "measurement.json", {"software_version": __version__, "python": platform.python_version(),
                                             "platform": platform.platform(), "cases": cases})
    for case in cases:
        print(f'{case["receipt_count"]} receipts, {case["threshold"]} of {case["roster_size"]} reviewer keys: '
              f'{case["quorum_gzip_bytes"]} bytes, {case["signatures_only"]["median_ms"]:.3f} ms signature, '
              f'{case["with_proof_recheck"]["median_ms"]:.3f} ms with recheck', flush=True)


if __name__ == "__main__":
    main()
