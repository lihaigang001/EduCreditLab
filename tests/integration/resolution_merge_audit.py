"""Compare merging existing publication witnesses with issuing their union from a full history."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, merge_resolution_witnesses,
                                               select_resolution_witness, verify_checkpoint_batch_resolution,
                                               verify_resolution_batch)
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, label, fixture, cuts, repeats, original, review, output):
    source_dir = source / "resolution-batch" / label
    archives = source / "resolution-checkpoint-extension"
    history_wire = (archives / fixture / "history.json.gz").read_bytes()
    pins = read_json(source_dir / "pins.json")
    numbers, trusted = pins["expected_publications"], pins["advanced_checkpoint_sha256"]
    batch = read_proof(source_dir / "refreshed-batch.json.gz")
    left, right = cuts
    groups = [numbers[:left], numbers[left - 1:right], numbers[right - 1:-1], numbers[-1:]]
    sources = [select_resolution_witness(batch, trusted, numbers=numbers, selected=group, single=len(group) == 1)
               for group in groups]
    source_wires = [gzip_proof(proof) for proof in sources]

    def full_audit():
        index = audit_resolution_checkpoint(decode_proof(history_wire), pins["initial_authority_sha256"],
                                            pins["latest_publication_sha256"])
        return index.batch_witness(numbers), index.fingerprint

    def merge():
        proof = merge_resolution_witnesses([decode_proof(wire) for wire in source_wires], trusted, numbers=numbers)
        return proof, digest(proof["checkpoint"])

    (expected, full_pin), full_time = time_trials(full_audit, repeats)
    (merged, merged_pin), merge_time = time_trials(merge, repeats)
    assert expected == merged == batch and full_pin == merged_pin == trusted
    assert merge_resolution_witnesses(sources[::-1], trusted, numbers=numbers[::-1]) == merged
    expect_rejection(lambda: merge_resolution_witnesses(sources[:-1], trusted, numbers=numbers),
                     "exactly the expected publication numbers")
    stale = read_proof(source_dir / "base-batch.json.gz")
    expect_rejection(lambda: merge_resolution_witnesses([*sources, stale], trusted, numbers=numbers),
                     "independently trusted publication checkpoint")
    status = verify_resolution_batch(merged, trusted, numbers=numbers)
    rechecked = pins["rechecked_publications"]
    for number, (packet, branch, key) in zip(rechecked, (
            ("outgoing", "left", "initial_authority_sha256"), ("incoming", "right", "incoming_authority_sha256"))):
        result = verify_checkpoint_batch_resolution(
            merged, read_proof(archives / f"{packet}-resolution.json.gz"), trusted, numbers=numbers, number=number,
            bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert result["proof_rechecked"] and result["verified_authority_sha256"] == pins[key]
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert result[field] == review[field]

    output.mkdir(parents=True, exist_ok=True)
    for index, wire in enumerate(source_wires, 1):
        write_bytes(output / f"source-{index}.json.gz", wire)
    merged_wire = gzip_proof(merged)
    write_bytes(output / "merged.json.gz", merged_wire)
    write_json(output / "pins.json", {**pins, "source_groups": groups})
    source_count = sum(len(group) for group in groups)
    return {"publication_count": status["publication_count"], "source_proof_count": len(sources),
            "source_membership_count": source_count, "union_count": len(numbers), "overlap_count": source_count - len(numbers),
            "full_history_gzip_bytes": len(history_wire), "sources_gzip_bytes": sum(map(len, source_wires)),
            "sources_array_gzip_bytes": len(gzip_proof(sources)), "merged_gzip_bytes": len(merged_wire),
            "full_audit": full_time, "merge": merge_time, "checkpoint_sha256": trusted, "matches_full_audit": True,
            "distinct_authorities": len({entry["verified_authority_sha256"] for entry in status["verified_publications"]}),
            "rechecked_publications": rechecked}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory of signed histories and retained publication batches")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    earlier = json.loads((source / "resolution-batch/measurement.json").read_text(encoding="utf-8"))
    review = earlier["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    specs = (("handover", "short", (3, 5)), ("mixed", "long", (12, 22)))
    cases = [measure(source, label, fixture, cuts, args.repeats, original, review, output / label)
             for label, fixture, cuts in specs]
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": review, "cases": cases})
    for case in cases:
        print(f'{case["source_membership_count"]} memberships -> {case["union_count"]} publications at '
              f'{case["publication_count"]}: {case["full_audit"]["median_ms"]:.3f} -> {case["merge"]["median_ms"]:.3f} ms, '
              f'{case["sources_array_gzip_bytes"]} -> {case["merged_gzip_bytes"]} bytes (array versus merged).')


if __name__ == "__main__":
    main()
