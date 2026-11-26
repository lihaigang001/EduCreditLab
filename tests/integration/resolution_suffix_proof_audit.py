"""Compare proof derivation from a signed continuation with existing publication audit paths."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (
    advance_and_merge_resolution_witnesses, audit_resolution_checkpoint, verify_checkpoint_batch_resolution,
    verify_resolution_batch,
)
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, label, fixture, repeats, original, review, output):
    retained = source / "resolution-advance-merge" / label
    archive = source / "resolution-checkpoint-extension"
    signed = archive / fixture
    pins = read_json(retained / "pins.json")
    base, latest, current = (pins[key] for key in ("base_checkpoint_sha256", "latest_publication_sha256",
                                                  "advanced_checkpoint_sha256"))
    base_size = pins["base_publication_count"]
    numbers = pins["expected_publications"]
    additions = [number for number in numbers if number > base_size]
    head_wire = (signed / "base-witness.json.gz").read_bytes()
    delta_wire = (signed / "delta.json.gz").read_bytes()
    history_wire = (signed / "history.json.gz").read_bytes()
    base_wires = [(retained / f"base-{index}.json.gz").read_bytes() for index in range(1, 5)]
    current_wires = [(retained / f"advanced-{index}.json.gz").read_bytes() for index in range(1, 3)]

    def audit():
        return audit_resolution_checkpoint(decode_proof(history_wire), pins["initial_authority_sha256"], latest)

    def from_continuation(wires, expected, selected=None):
        return advance_and_merge_resolution_witnesses(
            decode_proof(head_wire), decode_proof(delta_wire), [decode_proof(wire) for wire in wires],
            base, latest, numbers=expected, new_publications=selected)

    full, full_time = time_trials(lambda: audit().batch_witness(numbers), repeats)
    provided, provided_time = time_trials(lambda: from_continuation(base_wires + current_wires, numbers), repeats)
    combined, derived_time = time_trials(lambda: from_continuation(base_wires, numbers, additions), repeats)
    suffix, suffix_time = time_trials(lambda: from_continuation([], additions, additions), repeats)
    assert full == provided == combined == read_proof(retained / "combined.json.gz")
    assert suffix == audit().batch_witness(additions) and digest(combined["checkpoint"]) == current
    assert from_continuation(base_wires[::-1], numbers[::-1], additions[::-1]) == combined
    expect_rejection(lambda: from_continuation(base_wires, numbers, additions[:-1]), "exactly the expected publication numbers")
    expect_rejection(lambda: from_continuation(base_wires, numbers, [base_size]), "after the base checkpoint")
    checked = verify_resolution_batch(combined, current, numbers=numbers)
    verify_resolution_batch(suffix, current, numbers=additions)
    for number, (role, branch, key) in zip(pins["rechecked_publications"], (
            ("outgoing", "left", "initial_authority_sha256"), ("incoming", "right", "incoming_authority_sha256")), strict=True):
        result = verify_checkpoint_batch_resolution(
            combined, read_proof(archive / f"{role}-resolution.json.gz"), current, numbers=numbers, number=number,
            bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert result["proof_rechecked"] and result["verified_authority_sha256"] == pins[key]
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert result[field] == review[field]

    output.mkdir(parents=True, exist_ok=True)
    combined_wire, suffix_wire = gzip_proof(combined), gzip_proof(suffix)
    write_bytes(output / "combined.json.gz", combined_wire)
    write_bytes(output / "suffix-only.json.gz", suffix_wire)
    write_json(output / "pins.json", {**pins, "expected_new_publications": additions})
    suffix_input = len(head_wire) + len(delta_wire)
    derived_input = suffix_input + sum(map(len, base_wires))
    return {"base_publication_count": base_size, "publication_count": checked["publication_count"],
            "derived_publications": additions, "combined_count": len(numbers), "retained_base_witness_files": len(base_wires),
            "preissued_advanced_witness_files": len(current_wires), "full_history_gzip_bytes": len(history_wire),
            "preissued_input_gzip_bytes": derived_input + sum(map(len, current_wires)), "derived_input_gzip_bytes": derived_input,
            "suffix_only_input_gzip_bytes": suffix_input, "combined_gzip_bytes": len(combined_wire),
            "suffix_only_gzip_bytes": len(suffix_wire), "checkpoint_sha256": current,
            "full_audit": full_time, "preissued_merge": provided_time, "derived_merge": derived_time,
            "suffix_only": suffix_time, "combined_matches_full_audit": True, "suffix_matches_full_audit": True,
            "distinct_authorities": len({row["verified_authority_sha256"] for row in checked["verified_publications"]}),
            "rechecked_publications": pins["rechecked_publications"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory of signed continuations and retained witnesses")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    previous = json.loads((source / "resolution-advance-merge/measurement.json").read_text(encoding="utf-8"))
    review = previous["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    cases = [measure(source, label, fixture, args.repeats, original, review, output / label)
             for label, fixture in (("handover", "short"), ("mixed", "long"))]
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": review, "cases": cases})
    for case in cases:
        print(f'{case["publication_count"]} publications, derived {case["derived_publications"]}, '
              f'combined {case["combined_count"]}.')
        for method in ("full_audit", "preissued_merge", "derived_merge", "suffix_only"):
            print(f'  {method}: {case[method]["median_ms"]:.3f} ms')
        print(f'  preissued and derived merge inputs: {case["preissued_input_gzip_bytes"]} '
              f'and {case["derived_input_gzip_bytes"]} gzip bytes')


if __name__ == "__main__":
    main()
