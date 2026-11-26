"""Measure signed summaries and independent rechecks of packaged synthetic proofs."""

import argparse
from pathlib import Path
import json
import platform

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.lab import verify_review
from educreditlab.model import canonical, digest, read_json, write_bytes, write_json
from educreditlab.review_attestation import attest_review, reviewer_fingerprint, verify_attestation
from educreditlab.transport import decode_proof, gzip_proof


def measure(source, pins, key, repeats, output):
    proof_data = source.read_bytes()
    proof = decode_proof(proof_data)
    manifest, checkpoint, plan = (pins[name] for name in ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
    statement = attest_review(proof, key, manifest, checkpoint, plan)
    reviewer = reviewer_fingerprint(statement["body"]["reviewer_public_key"])
    signed_data = gzip_proof(statement)

    def verify_summary():
        return verify_attestation(decode_proof(signed_data), reviewer, plan)

    def recheck():
        return verify_attestation(decode_proof(signed_data), reviewer, plan, trusted_manifest=manifest,
                                  trusted_checkpoint=checkpoint, proof=decode_proof(proof_data))

    signature, signature_timing = time_trials(verify_summary, repeats)
    reviewed, recheck_timing = time_trials(recheck, repeats)
    original = verify_review(proof, manifest, trusted_checkpoint=checkpoint, trusted_plan=plan)
    assert signature["signature_verified"] and not signature["proof_rechecked"] and reviewed["proof_rechecked"]
    assert signature["result_sha256"] == reviewed["result_sha256"] == digest(original)
    assert signature["proof_sha256"] == reviewed["proof_sha256"] == digest(proof)
    assert all(field not in canonical(statement)
               for field in (b'"evidence"', b'"transcript"', b'"attempts"', b'"decision"', b'"receipts"'))
    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "attestation.json.gz", signed_data)
    write_json(output / "pins.json", {**pins, "reviewer_sha256": reviewer, "proof_sha256": digest(proof)})
    return {**{field: reviewed[field] for field in ("receipt_count", "replay_count", "anchor_count",
                                                    "checkpoint_height", "review_plan_sha256", "proof_sha256",
                                                    "result_sha256")},
            "statement_gzip_bytes": len(signed_data), "proof_gzip_bytes": len(proof_data),
            "signature_only": signature_timing, "with_proof_recheck": recheck_timing,
            "independent_result_match": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results/review-plan", help="Directory of the packaged synthetic review plans")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    demo = read_json(source / "demo/pins.json")
    large = json.loads((source / "measurement.json").read_text(encoding="utf-8"))
    pins = {"manifest_sha256": large["checkpoint"]["manifest_sha256"],
            "checkpoint_sha256": large["checkpoint_sha256"],
            "review_plan_sha256": large["cases"][1]["review_plan_sha256"]}
    assert pins["review_plan_sha256"] == digest(read_json(source / "plan.json"))
    key = Ed25519PrivateKey.generate()
    cases = [measure(source / "demo/review.json.gz", demo, key, args.repeats, output / "three"),
             measure(source / "review-128.json.gz", pins, key, args.repeats, output / "128")]
    write_json(output / "measurement.json", {"software_version": __version__, "python": platform.python_version(),
                                             "platform": platform.platform(), "cases": cases})
    for case in cases:
        print(f'{case["receipt_count"]} receipts: {case["statement_gzip_bytes"]} statement bytes, '
              f'{case["proof_gzip_bytes"]} proof bytes, {case["signature_only"]["median_ms"]:.3f} ms signature, '
              f'{case["with_proof_recheck"]["median_ms"]:.3f} ms with recheck', flush=True)


if __name__ == "__main__":
    main()
