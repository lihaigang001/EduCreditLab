"""Compare one-pass checkpoint chain reconciliation with staged merges and a full audit."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (
    advance_and_merge_resolution_witnesses, advance_chain_and_merge_resolution_witnesses,
    audit_resolution_checkpoint, resolution_checkpoint_delta, verify_checkpoint_batch_resolution,
    verify_resolution_batch,
)
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, label, fixture, repeats, original, review, output):
    retained = source / "resolution-advance-merge" / label
    archives = source / "resolution-checkpoint-extension"
    signed = archives / fixture
    pins = read_json(retained / "pins.json")
    base, latest, current = (pins[key] for key in ("base_checkpoint_sha256", "latest_publication_sha256",
                                                  "advanced_checkpoint_sha256"))
    base_size = pins["base_publication_count"]
    interim_size = base_size + 3
    base_numbers = [number for number in pins["expected_publications"] if number <= base_size]
    history_wire = (signed / "history.json.gz").read_bytes()
    head_wire = (signed / "base-witness.json.gz").read_bytes()
    base_wires = [(retained / f"base-{index}.json.gz").read_bytes() for index in range(1, 5)]

    def audit():
        return audit_resolution_checkpoint(decode_proof(history_wire), pins["initial_authority_sha256"], latest)

    index = audit()
    final_size = index.descriptor["publication_count"]
    assert index.fingerprint == current and final_size - base_size == 8
    history = decode_proof(history_wire)
    prefix = {**history, "publications": history["publications"][:interim_size]}
    intermediate_tip = digest(prefix["publications"][-1]["body"])
    authority = pins["initial_authority_sha256"]
    intermediate = audit_resolution_checkpoint(prefix, authority, intermediate_tip)
    tips = [intermediate_tip, latest]
    deltas = [resolution_checkpoint_delta(prefix, authority, intermediate_tip, from_number=base_size),
              resolution_checkpoint_delta(history, authority, latest, from_number=interim_size)]
    delta_wires = [gzip_proof(delta) for delta in deltas]
    interim_head_wire = gzip_proof(intermediate.witness())
    middle_wire = gzip_proof(intermediate.batch_witness([1, 2, base_size + 2]))
    final_wire = gzip_proof(index.witness(final_size))
    initial_selection = [base_size + 1]
    final_selection = [final_size - 1]
    additions = initial_selection + final_selection
    first_numbers = sorted({*base_numbers, 2, base_size + 1, base_size + 2})
    numbers = sorted({*first_numbers, *final_selection, final_size})

    def from_chain(wires, steps=delta_wires, expected_tips=tips):
        return advance_chain_and_merge_resolution_witnesses(
            decode_proof(head_wire), [decode_proof(wire) for wire in steps], [decode_proof(wire) for wire in wires],
            base, expected_tips, numbers=numbers, new_publications=additions)

    def sequential():
        prior = advance_and_merge_resolution_witnesses(
            decode_proof(head_wire), decode_proof(delta_wires[0]),
            [decode_proof(wire) for wire in [*base_wires, middle_wire]], base, tips[0],
            numbers=first_numbers, new_publications=initial_selection)
        return advance_and_merge_resolution_witnesses(
            decode_proof(interim_head_wire), decode_proof(delta_wires[1]), [prior, decode_proof(final_wire)],
            digest(prior["checkpoint"]), tips[1], numbers=numbers, new_publications=final_selection)

    source_wires = [*base_wires, middle_wire, final_wire]
    full, full_time = time_trials(lambda: audit().batch_witness(numbers), repeats)
    staged, staged_time = time_trials(sequential, repeats)
    combined, combined_time = time_trials(lambda: from_chain(source_wires), repeats)
    assert full == staged == combined and digest(combined["checkpoint"]) == current
    assert from_chain(source_wires[::-1]) == combined
    expect_rejection(lambda: from_chain([*base_wires, final_wire]), "exactly the expected publication numbers")
    expect_rejection(lambda: from_chain(source_wires, delta_wires[::-1], tips[::-1]), "delta base publication count")
    expect_rejection(lambda: from_chain(source_wires, expected_tips=[latest, latest]),
                     "independently expected latest publication")
    checked = verify_resolution_batch(combined, current, numbers=numbers)
    for number, (role, branch, key) in zip(pins["rechecked_publications"], (
            ("outgoing", "left", "initial_authority_sha256"), ("incoming", "right", "incoming_authority_sha256")), strict=True):
        result = verify_checkpoint_batch_resolution(
            combined, read_proof(archives / f"{role}-resolution.json.gz"), current, numbers=numbers, number=number,
            bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert result["proof_rechecked"] and result["verified_authority_sha256"] == pins[key]
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert result[field] == review[field]

    output.mkdir(parents=True, exist_ok=True)
    combined_wire = gzip_proof(combined)
    for name, data in (("delta-1", delta_wires[0]), ("delta-2", delta_wires[1]), ("intermediate", middle_wire),
                       ("intermediate-head", interim_head_wire), ("final", final_wire), ("combined", combined_wire)):
        write_bytes(output / f"{name}.json.gz", data)
    write_json(output / "pins.json", {**pins, "stage_publication_sha256": tips,
                                     "intermediate_checkpoint_sha256": intermediate.fingerprint,
                                     "expected_publications": numbers, "expected_new_publications": additions})
    input_bytes = len(head_wire) + sum(map(len, delta_wires + source_wires))
    return {"checkpoint_counts": [base_size, interim_size, final_size], "stage_publication_sha256": tips,
            "stage_publication_counts": [len(delta["publications"]) for delta in deltas],
            "retained_witness_files": len(source_wires), "derived_publications": additions,
            "combined_count": len(numbers), "full_history_gzip_bytes": len(history_wire),
            "chain_input_gzip_bytes": input_bytes, "sequential_input_gzip_bytes": input_bytes + len(interim_head_wire),
            "combined_gzip_bytes": len(combined_wire), "checkpoint_sha256": current,
            "full_audit": full_time, "sequential_merge": staged_time, "chain_merge": combined_time,
            "matches_full_audit": True, "matches_sequential_merge": True,
            "distinct_authorities": len({row["verified_authority_sha256"] for row in checked["verified_publications"]}),
            "rechecked_publications": pins["rechecked_publications"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory of signed histories and retained witnesses")
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
        print(f'{case["checkpoint_counts"]}: {case["combined_count"]} publications with '
              f'{len(case["derived_publications"])} derived from signed continuations.')
        for method in ("full_audit", "sequential_merge", "chain_merge"):
            print(f'  {method}: {case[method]["median_ms"]:.3f} ms')


if __name__ == "__main__":
    main()
