"""Compare four ways to combine proofs from either side of a signed checkpoint extension."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (
    advance_and_merge_resolution_witnesses, audit_resolution_checkpoint, extend_resolution_checkpoint,
    merge_resolution_witnesses, refresh_resolution_batch, refresh_resolution_witness,
    verify_checkpoint_batch_resolution, verify_resolution_batch,
)
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, label, fixture, cuts, repeats, original, review, output):
    archives = source / "resolution-checkpoint-extension"
    signed = archives / fixture
    history_wire = (signed / "history.json.gz").read_bytes()
    head_wire = (signed / "base-witness.json.gz").read_bytes()
    delta_wire = (signed / "delta.json.gz").read_bytes()
    pins = read_json(signed / "pins.json")
    base, latest, current = (pins[k] for k in ("base_checkpoint_sha256", "latest_publication_sha256",
                                              "advanced_checkpoint_sha256"))
    base_count = pins["base_publication_count"]
    first_new = base_count + 1
    selection = read_json(source / "resolution-batch" / label / "pins.json")["expected_publications"]
    old_numbers = [number for number in selection if number <= base_count]

    def audit():
        return audit_resolution_checkpoint(decode_proof(history_wire), pins["initial_authority_sha256"], latest)

    index = audit()
    assert index.fingerprint == current
    history = decode_proof(history_wire)
    prefix = {**history, "publications": history["publications"][:base_count]}
    base_index = audit_resolution_checkpoint(prefix, pins["initial_authority_sha256"], pins["base_publication_sha256"])
    assert base_index.fingerprint == base
    left, right = cuts
    base_groups = [old_numbers[:left], old_numbers[left - 1:right], old_numbers[right - 1:-1], old_numbers[-1:]]
    current_groups = [[old_numbers[-1], first_new, index.descriptor["publication_count"]], [first_new + 1]]
    previous = [base_index.witness(group[0]) if len(group) == 1 else base_index.batch_witness(group)
                for group in base_groups]
    advanced = [index.batch_witness(current_groups[0]), index.witness(current_groups[1][0])]
    previous_wires, advanced_wires = [gzip_proof(proof) for proof in previous], [gzip_proof(proof) for proof in advanced]
    numbers = sorted({number for group in [*base_groups, *current_groups] for number in group})

    def inputs():
        return (decode_proof(head_wire), decode_proof(delta_wire), [decode_proof(wire) for wire in previous_wires],
                [decode_proof(wire) for wire in advanced_wires])

    def separate_refreshes():
        head, delta, archived, carried = inputs()
        refreshed = []
        for proof, group in zip(archived, base_groups, strict=True):
            if len(group) == 1:
                result = refresh_resolution_witness(head, delta, proof, base, latest, number=group[0])
            else:
                result = refresh_resolution_batch(head, delta, proof, base, latest, numbers=group)
            refreshed.append(result)
        pin = digest(refreshed[0]["checkpoint"])
        return merge_resolution_witnesses([*refreshed, *carried], pin, numbers=numbers)

    def grouped_refresh():
        head, delta, archived, carried = inputs()
        merged = merge_resolution_witnesses(archived, base, numbers=old_numbers)
        refreshed = refresh_resolution_batch(head, delta, merged, base, latest, numbers=old_numbers)
        return merge_resolution_witnesses([refreshed, *carried], digest(refreshed["checkpoint"]), numbers=numbers)

    def advance_merge():
        head, delta, archived, carried = inputs()
        return advance_and_merge_resolution_witnesses(head, delta, [*archived, *carried], base, latest, numbers=numbers)

    full, full_time = time_trials(lambda: audit().batch_witness(numbers), repeats)
    separate, separate_time = time_trials(separate_refreshes, repeats)
    grouped, grouped_time = time_trials(grouped_refresh, repeats)
    combined, combined_time = time_trials(advance_merge, repeats)
    assert full == separate == grouped == combined and digest(combined["checkpoint"]) == current
    head, delta = decode_proof(head_wire), decode_proof(delta_wire)
    reordered = [advanced[1], previous[2], previous[0], advanced[0], previous[3], previous[1]]
    assert advance_and_merge_resolution_witnesses(head, delta, reordered, base, latest, numbers=numbers[::-1]) == combined
    expect_rejection(lambda: advance_and_merge_resolution_witnesses(
        head, delta, [*previous, advanced[0]], base, latest, numbers=numbers), "exactly the expected publication numbers")
    assert extend_resolution_checkpoint(head, delta, base, latest)["checkpoint"] == combined["checkpoint"]
    checked = verify_resolution_batch(combined, current, numbers=numbers)
    rechecked = [1, first_new]
    for number, (role, branch, key) in zip(rechecked, (("outgoing", "left", "initial_authority_sha256"),
                                                      ("incoming", "right", "incoming_authority_sha256")), strict=True):
        result = verify_checkpoint_batch_resolution(
            combined, read_proof(archives / f"{role}-resolution.json.gz"), current, numbers=numbers, number=number,
            bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert result["proof_rechecked"] and result["verified_authority_sha256"] == pins[key]
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert result[field] == review[field]

    output.mkdir(parents=True, exist_ok=True)
    for name, wires in (("base", previous_wires), ("advanced", advanced_wires)):
        for ordinal, wire in enumerate(wires, 1):
            write_bytes(output / f"{name}-{ordinal}.json.gz", wire)
    combined_wire = gzip_proof(combined)
    write_bytes(output / "combined.json.gz", combined_wire)
    write_json(output / "pins.json", {**pins, "expected_publications": numbers, "base_groups": base_groups,
                                     "advanced_groups": current_groups, "rechecked_publications": rechecked})
    groups = base_groups + current_groups
    return {"base_publication_count": base_count, "publication_count": checked["publication_count"],
            "base_proof_count": len(previous), "advanced_proof_count": len(advanced),
            "source_membership_count": sum(map(len, groups)), "union_count": len(numbers),
            "base_head_gzip_bytes": len(head_wire), "delta_gzip_bytes": len(delta_wire),
            "source_proof_gzip_bytes": sum(map(len, previous_wires + advanced_wires)),
            "full_history_gzip_bytes": len(history_wire), "combined_gzip_bytes": len(combined_wire),
            "full_audit": full_time, "separate_refreshes": separate_time, "grouped_refresh": grouped_time,
            "advance_merge": combined_time, "matches_full_audit": True, "checkpoint_sha256": current,
            "distinct_authorities": len({entry["verified_authority_sha256"] for entry in checked["verified_publications"]}),
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
    review = json.loads((source / "resolution-batch/measurement.json").read_text(encoding="utf-8"))["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    fixtures = (("handover", "short", (2, 4)), ("mixed", "long", (10, 20)))
    cases = [measure(source, label, fixture, cuts, args.repeats, original, review, output / label)
             for label, fixture, cuts in fixtures]
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": review, "cases": cases})
    for case in cases:
        print(f'{case["source_membership_count"]} memberships -> {case["union_count"]} publications at '
              f'{case["base_publication_count"]} -> {case["publication_count"]}.')
        for method in ("full_audit", "separate_refreshes", "grouped_refresh", "advance_merge"):
            print(f'  {method}: {case[method]["median_ms"]:.3f} ms')


if __name__ == "__main__":
    main()
