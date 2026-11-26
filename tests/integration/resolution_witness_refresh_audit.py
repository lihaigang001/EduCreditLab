"""Compare archived witness refresh with the same witness from a full signed audit."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, refresh_resolution_witness,
                                               verify_checkpoint_resolution, verify_resolution_witness)
from educreditlab.transport import decode_proof, gzip_proof, read_proof

ARCHIVED_PUBLICATION = 1


def measure(source, fixture, output, repeats, original, review):
    history_wire = (fixture / "history.json.gz").read_bytes()
    head_wire = (fixture / "base-witness.json.gz").read_bytes()
    delta_wire = (fixture / "delta.json.gz").read_bytes()
    pins = read_json(fixture / "pins.json")
    base_size = pins["base_publication_count"]
    initial, tip = pins["initial_authority_sha256"], pins["latest_publication_sha256"]
    base_pin, new_pin = pins["base_checkpoint_sha256"], pins["advanced_checkpoint_sha256"]
    history = decode_proof(history_wire)
    base = {**history, "publications": history["publications"][:base_size]}
    old_index = audit_resolution_checkpoint(base, initial, pins["base_publication_sha256"])
    assert old_index.fingerprint == base_pin
    assert old_index.witness() == decode_proof(head_wire)
    archived = old_index.witness(ARCHIVED_PUBLICATION)
    archived_wire = gzip_proof(archived)

    def full_audit():
        index = audit_resolution_checkpoint(decode_proof(history_wire), initial, tip)
        return index.witness(ARCHIVED_PUBLICATION), index.fingerprint

    def refresh():
        witness = refresh_resolution_witness(decode_proof(head_wire), decode_proof(delta_wire),
                                             decode_proof(archived_wire), base_pin, tip, number=ARCHIVED_PUBLICATION)
        return witness, digest(witness["checkpoint"])

    expected, audit_time = time_trials(full_audit, repeats)
    (refreshed, fingerprint), refresh_time = time_trials(refresh, repeats)
    assert (refreshed, fingerprint) == expected
    assert fingerprint == new_pin and refreshed["entry"] == archived["entry"]
    assert refreshed["entry"]["authority_sha256"] == initial
    head = read_proof(fixture / "advanced-witness.json.gz")
    assert refreshed["checkpoint"] == head["checkpoint"]
    assert head["entry"]["authority_sha256"] == pins["incoming_authority_sha256"]
    expect_rejection(lambda: verify_resolution_witness(archived, new_pin, number=ARCHIVED_PUBLICATION),
                     "independently trusted publication checkpoint")
    expect_rejection(lambda: verify_resolution_witness(refreshed, base_pin, number=ARCHIVED_PUBLICATION),
                     "independently trusted publication checkpoint")

    for label, branch, witness, authority, number in (
            ("outgoing", "left", refreshed, initial, ARCHIVED_PUBLICATION),
            ("incoming", "right", head, pins["incoming_authority_sha256"], None)):
        result = verify_checkpoint_resolution(
            witness, read_proof(fixture.parent / f"{label}-resolution.json.gz"), new_pin, number=number,
            bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert result["proof_rechecked"] and result["verified_authority_sha256"] == authority
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert result[field] == review[field]

    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "archived-witness.json.gz", archived_wire)
    write_bytes(output / "refreshed-witness.json.gz", gzip_proof(refreshed))
    write_json(output / "pins.json", {**pins, "archived_publication": ARCHIVED_PUBLICATION,
                                     "archived_authority_sha256": refreshed["entry"]["authority_sha256"],
                                     "archived_decision_sha256": refreshed["entry"]["decision_sha256"]})
    return {"base_publication_count": base_size, "publication_count": refreshed["checkpoint"]["publication_count"],
            "archived_publication": ARCHIVED_PUBLICATION, "history_gzip_bytes": len(history_wire),
            "base_head_gzip_bytes": len(head_wire), "base_archived_gzip_bytes": len(archived_wire),
            "delta_gzip_bytes": len(delta_wire), "refresh_input_gzip_bytes": len(head_wire) + len(delta_wire) + len(archived_wire),
            "old_sibling_count": len(archived["siblings"]), "new_sibling_count": len(refreshed["siblings"]),
            "full_audit": audit_time, "refresh": refresh_time, "advanced_checkpoint_sha256": fingerprint,
            "matches_full_audit": True, "archived_and_current_evidence_rechecked": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory containing the signed v1.18.0 publication examples")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    fixture = source / "resolution-checkpoint-extension"
    previous = json.loads((fixture / "measurement.json").read_text(encoding="utf-8"))
    review = previous["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    cases = [measure(source, fixture / label, output / label, args.repeats, original, review)
             for label in ("short", "long")]
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": review, "cases": cases})
    for case in cases:
        print(f'publication {case["archived_publication"]} at {case["base_publication_count"]} -> {case["publication_count"]}: '
              f'{case["history_gzip_bytes"]} -> {case["refresh_input_gzip_bytes"]} bytes, '
              f'{case["full_audit"]["median_ms"]:.3f} -> {case["refresh"]["median_ms"]:.3f} ms, '
              "identical full and refreshed witnesses")


if __name__ == "__main__":
    main()
