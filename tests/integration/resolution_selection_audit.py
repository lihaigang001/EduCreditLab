"""Compare proof selection from a retained publication batch with a full audit."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, select_resolution_witness,
                                               verify_checkpoint_batch_resolution, verify_checkpoint_resolution,
                                               verify_resolution_batch)
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, label, fixture, target, ordinal, repeats, original, review, output):
    base = source / "resolution-batch" / label
    archives = source / "resolution-checkpoint-extension"
    history_wire = (archives / fixture / "history.json.gz").read_bytes()
    source_wire = (base / "refreshed-batch.json.gz").read_bytes()
    pins = read_json(base / "pins.json")
    source_numbers, trusted = pins["expected_publications"], pins["advanced_checkpoint_sha256"]

    def full_audit():
        index = audit_resolution_checkpoint(decode_proof(history_wire), pins["initial_authority_sha256"],
                                            pins["latest_publication_sha256"])
        return index.batch_witness(target), index.fingerprint

    def select(numbers, single=False):
        result = select_resolution_witness(decode_proof(source_wire), trusted, numbers=source_numbers,
                                           selected=numbers, single=single)
        return result, digest(result["checkpoint"])

    (full, full_pin), full_time = time_trials(full_audit, repeats)
    (selected, selected_pin), selected_time = time_trials(lambda: select(target), repeats)
    (single, single_pin), single_time = time_trials(lambda: select([ordinal], single=True), repeats)
    assert selected == full and full_pin == selected_pin == single_pin == trusted
    native = audit_resolution_checkpoint(decode_proof(history_wire), pins["initial_authority_sha256"],
                                         pins["latest_publication_sha256"]).witness(ordinal)
    assert single == native
    verified = verify_resolution_batch(selected, trusted, numbers=target)
    expect_rejection(lambda: verify_resolution_batch(selected, trusted, numbers=source_numbers), "publication batch entries")
    expect_rejection(lambda: select_resolution_witness(decode_proof(source_wire), trusted, numbers=source_numbers,
                                                      selected=[verified["publication_count"]]),
                     "distinct leaves proved by the source batch")

    def evidence(branch):
        return {"bundle": read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"),
                "proof": original, "trusted_manifest": review["manifest_sha256"],
                "trusted_checkpoint": review["checkpoint_sha256"], "expected_proof": review["proof_sha256"]}

    def compare(result, authority):
        assert result["proof_rechecked"] and result["verified_authority_sha256"] == authority
        for key in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert result[key] == review[key]

    rechecked = pins["rechecked_publications"]
    for number, (packet, branch, authority_key) in zip(rechecked, (
            ("outgoing", "left", "initial_authority_sha256"), ("incoming", "right", "incoming_authority_sha256"))):
        resolution = read_proof(archives / f"{packet}-resolution.json.gz")
        result = verify_checkpoint_batch_resolution(selected, resolution, trusted, numbers=target, number=number,
                                                    **evidence(branch))
        compare(result, pins[authority_key])
        if number == ordinal:
            compare(verify_checkpoint_resolution(single, resolution, trusted, number=number, **evidence(branch)),
                    pins[authority_key])

    output.mkdir(parents=True, exist_ok=True)
    subset_wire, single_wire = gzip_proof(selected), gzip_proof(single)
    write_bytes(output / "subset.json.gz", subset_wire)
    write_bytes(output / "single.json.gz", single_wire)
    write_json(output / "pins.json", {**pins, "selected_publications": target, "single_publication": ordinal})
    return {"publication_count": verified["publication_count"], "source_count": len(source_numbers),
            "selected_count": len(target), "source_gzip_bytes": len(source_wire), "subset_gzip_bytes": len(subset_wire),
            "single_gzip_bytes": len(single_wire), "history_gzip_bytes": len(history_wire),
            "full_audit": full_time, "select_from_batch": selected_time, "select_single": single_time,
            "distinct_selected_authorities": len({entry["verified_authority_sha256"] for entry in verified["verified_publications"]}),
            "checkpoint_sha256": trusted, "same_as_full_audit": True, "matches_native_single": True,
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
    upstream = json.loads((source / "resolution-batch/measurement.json").read_text(encoding="utf-8"))
    review = upstream["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    specs = (("handover", "short", [1, 31], 1), ("mixed", "long", [1, 33, 1024, 1025], 1024))
    cases = [measure(source, label, fixture, target, ordinal, args.repeats, original, review, output / label)
             for label, fixture, target, ordinal in specs]
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": review, "cases": cases})
    for case in cases:
        print(f'{case["source_count"]} -> {case["selected_count"]} leaves at {case["publication_count"]} publications: '
              f'{case["full_audit"]["median_ms"]:.3f} -> {case["select_from_batch"]["median_ms"]:.3f} ms, '
              f'{case["source_gzip_bytes"]} -> {case["subset_gzip_bytes"]} bytes; '
              f'single {case["single_gzip_bytes"]} bytes.')


if __name__ == "__main__":
    main()
