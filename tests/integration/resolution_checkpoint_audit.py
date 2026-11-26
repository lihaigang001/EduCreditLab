"""Compare full publication-history audit with review against an audited checkpoint."""

import argparse
import json
import platform
from pathlib import Path

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, verify_checkpoint_resolution,
                                               verify_resolution_witness)
from educreditlab.resolution_history import verify_published_resolution, verify_resolution_history
from educreditlab.transport import decode_proof, gzip_proof


def measure(history, pins, reviews, original_bytes, expected_review, repeats, output):
    initial, tip = pins["initial_authority_sha256"], pins["latest_publication_sha256"]
    baseline, history_time = time_trials(lambda: verify_resolution_history(decode_proof(history), initial, tip), repeats)

    def audit():
        index = audit_resolution_checkpoint(decode_proof(history), initial, tip)
        return index, index.fingerprint

    (index, checkpoint_pin), audit_time = time_trials(audit, repeats)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "checkpoint.json", index.descriptor)
    write_json(output / "pins.json", {**pins, "publication_checkpoint_sha256": checkpoint_pin})
    cases = []
    for label, number, packet, confirmation in reviews:
        witness = index.witness(number)
        wire = gzip_proof(witness)

        def verify_compact(**evidence):
            return verify_checkpoint_resolution(
                decode_proof(wire), decode_proof(packet), checkpoint_pin, number=number,
                bundle=decode_proof(confirmation), **evidence)

        selected, witness_time = time_trials(
            lambda: verify_resolution_witness(decode_proof(wire), checkpoint_pin, number=number), repeats)
        full, full_time = time_trials(
            lambda: verify_published_resolution(decode_proof(history), decode_proof(packet), initial, tip,
                                                number=number, bundle=decode_proof(confirmation)), repeats)
        compact, compact_time = time_trials(verify_compact, repeats)
        checked = verify_compact(proof=decode_proof(original_bytes), trusted_manifest=expected_review["manifest_sha256"],
                                 trusted_checkpoint=expected_review["checkpoint_sha256"],
                                 expected_proof=expected_review["proof_sha256"])
        for field in ("verified_publication", "verified_publication_sha256", "verified_authority_sha256",
                      "decision_sha256", "selected_revision_sha256", "result_sha256"):
            assert full[field] == compact[field], field
        assert selected["is_checkpoint_head"] == (number is None)
        pin = "initial_authority_sha256" if number is not None else "active_authority_sha256"
        assert selected["verified_authority_sha256"] == pins[pin]
        assert selected["publication_count"] == baseline["publication_count"]
        assert checked["proof_rechecked"] and not compact["proof_rechecked"]
        for field in ("receipt_count", "replay_count", "anchor_count", "result_sha256", "proof_sha256"):
            assert checked[field] == expected_review[field], field
        write_bytes(output / f"{label}-witness.json.gz", wire)
        cases.append({"selection": label, "publication": selected["verified_publication"],
                      "is_checkpoint_head": selected["is_checkpoint_head"], "path_hashes": len(witness["siblings"]),
                      "verified_authority_sha256": selected["verified_authority_sha256"],
                      "verified_decision_sha256": selected["verified_decision_sha256"],
                      "witness_gzip_bytes": len(wire), "verify_witness": witness_time,
                      "full_history_review": full_time, "checkpoint_review": compact_time,
                      "resolution_gzip_bytes": len(packet), "confirmation_gzip_bytes": len(confirmation),
                      "original_evidence_rechecked": checked["proof_rechecked"],
                      "result_sha256": checked["result_sha256"]})
    return {"publication_count": baseline["publication_count"], "history_gzip_bytes": len(history),
            "verify_full_history": history_time, "audit_publication_checkpoint": audit_time,
            "publication_checkpoint_sha256": checkpoint_pin, "witnesses": cases}


def experiment(source, output, repeats):
    handover = source / "resolution-handover"
    branch = source / "policy-divergence/long"
    reviews = [(label, number, (handover / f"{authority}-resolution.json.gz").read_bytes(),
                (branch / f"{side}-quorum.json.gz").read_bytes())
               for label, number, authority, side in (("archived", 1, "outgoing", "left"),
                                                     ("head", None, "incoming", "right"))]
    original = (source / "review-plan/review-128.json.gz").read_bytes()
    expected = json.loads((handover / "measurement.json").read_text(encoding="utf-8"))["review"]
    assert digest(decode_proof(original)) == expected["proof_sha256"]
    cases = [measure((handover / label / "history.json.gz").read_bytes(), read_json(handover / label / "pins.json"),
                     reviews, original, expected, repeats, output / label) for label in ("short", "long")]
    return {"repeats": repeats, "original_review": expected, "handover_publication": 2, "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory containing the v1.16.0 publication fixtures")
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
        for witness in case["witnesses"]:
            print(f'{case["publication_count"]} publications, {witness["selection"]}: '
                  f'{case["history_gzip_bytes"]} -> {witness["witness_gzip_bytes"]} bytes, '
                  f'{witness["verify_witness"]["median_ms"]:.3f} ms inclusion verification, '
                  f'{witness["full_history_review"]["median_ms"]:.3f} -> '
                  f'{witness["checkpoint_review"]["median_ms"]:.3f} ms combined review')


if __name__ == "__main__":
    main()
