"""Compare shared publication batch refresh with full audit and separate witness refreshes."""

import argparse
import json
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, refresh_resolution_batch,
                                               refresh_resolution_witness, resolution_checkpoint_delta,
                                               verify_checkpoint_batch_resolution, verify_resolution_batch)
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, fixture, output, specification, repeats, original, review):
    base_size, numbers = specification
    history_wire = (fixture / "history.json.gz").read_bytes()
    source_pins = read_json(fixture / "pins.json")
    initial, tip = source_pins["initial_authority_sha256"], source_pins["latest_publication_sha256"]
    history = decode_proof(history_wire)
    base_history = {**history, "publications": history["publications"][:base_size]}
    base_tip = digest(base_history["publications"][-1]["body"])
    base = audit_resolution_checkpoint(base_history, initial, base_tip)
    base_pin = base.fingerprint
    batch_wire = gzip_proof(base.batch_witness(numbers))
    head_wire = gzip_proof(base.witness())
    delta_wire = gzip_proof(resolution_checkpoint_delta(history, initial, tip, from_number=base_size))
    individual_wires = [gzip_proof(base.witness(number)) for number in numbers]

    def full_audit():
        index = audit_resolution_checkpoint(decode_proof(history_wire), initial, tip)
        return index.batch_witness(numbers), index.fingerprint

    def batch_refresh():
        advanced = refresh_resolution_batch(decode_proof(head_wire), decode_proof(delta_wire), decode_proof(batch_wire),
                                            base_pin, tip, numbers=numbers)
        return advanced, digest(advanced["checkpoint"])

    def separate_refreshes():
        head, delta = decode_proof(head_wire), decode_proof(delta_wire)
        refreshed = [refresh_resolution_witness(head, delta, decode_proof(wire), base_pin, tip, number=number)
                     for number, wire in zip(numbers, individual_wires, strict=True)]
        return refreshed, digest(refreshed[0]["checkpoint"])

    expected, full_time = time_trials(full_audit, repeats)
    (advanced, new_pin), batch_time = time_trials(batch_refresh, repeats)
    (individual, individual_pin), individual_time = time_trials(separate_refreshes, repeats)
    assert (advanced, new_pin) == expected
    assert new_pin == individual_pin == source_pins["advanced_checkpoint_sha256"]
    assert advanced["entries"] == [witness["entry"] for witness in individual]
    assert all(witness["checkpoint"] == advanced["checkpoint"] for witness in individual)
    checked = verify_resolution_batch(advanced, new_pin, numbers=list(reversed(numbers)))
    expect_rejection(lambda: verify_resolution_batch(advanced, new_pin, numbers=numbers[:-1]), "publication batch entries")
    expect_rejection(lambda: verify_resolution_batch(decode_proof(batch_wire), new_pin, numbers=numbers),
                     "independently trusted publication checkpoint")

    selections = {selection["verified_authority_sha256"]: selection["verified_publication"]
                  for selection in reversed(checked["verified_publications"])}
    verified_numbers = []
    for label, branch, authority in (("outgoing", "left", initial), ("incoming", "right", source_pins["incoming_authority_sha256"])):
        if authority not in selections:
            continue
        number = selections[authority]
        verdict = verify_checkpoint_batch_resolution(
            advanced, read_proof(fixture.parent / f"{label}-resolution.json.gz"), new_pin, numbers=numbers,
            number=number, bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert verdict["proof_rechecked"] and verdict["verified_authority_sha256"] == authority
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert verdict[field] == review[field]
        verified_numbers.append(number)
    assert len(verified_numbers) == len(selections) == (1 if base_size == 31 else 2)

    output.mkdir(parents=True, exist_ok=True)
    advanced_wire = gzip_proof(advanced)
    for label, wire in (("base-head.json.gz", head_wire), ("delta.json.gz", delta_wire),
                        ("base-batch.json.gz", batch_wire), ("refreshed-batch.json.gz", advanced_wire)):
        write_bytes(output / label, wire)
    write_json(output / "pins.json", {"initial_authority_sha256": initial,
                                     "incoming_authority_sha256": source_pins["incoming_authority_sha256"],
                                     "base_publication_sha256": base_tip, "expected_publications": numbers,
                                     "base_checkpoint_sha256": base_pin, "latest_publication_sha256": tip,
                                     "advanced_checkpoint_sha256": new_pin, "rechecked_publications": verified_numbers})
    return {"base_publication_count": base_size, "publication_count": checked["publication_count"],
            "selected_publication_count": len(numbers), "verified_new_publications": checked["publication_count"] - base_size,
            "distinct_authorities": len(selections), "full_audit": full_time, "separate_refreshes": individual_time,
            "batch_refresh": batch_time, "history_gzip_bytes": len(history_wire),
            "batch_refresh_input_gzip_bytes": len(head_wire) + len(delta_wire) + len(batch_wire),
            "separate_output_gzip_bytes": len(gzip_proof(individual)), "batch_output_gzip_bytes": len(advanced_wire),
            "separate_sibling_count": sum(len(witness["siblings"]) for witness in individual),
            "batch_sibling_count": len(advanced["siblings"]), "advanced_checkpoint_sha256": new_pin,
            "matches_full_audit": True, "rechecked_publications": verified_numbers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory containing signed publication and receipt fixtures")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    fixtures = source / "resolution-checkpoint-extension"
    previous = json.loads((fixtures / "measurement.json").read_text(encoding="utf-8"))
    review = previous["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    specifications = (("short", "handover", (31, [1, 5, 9, 13, 17, 21, 25, 31])),
                      ("long", "mixed", (1025, [1 + 32 * i for i in range(30)] + [1024, 1025])))
    cases = [measure(source, fixtures / fixture, output / label, specification, args.repeats, original, review)
             for fixture, label, specification in specifications]
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": review, "cases": cases})
    for case in cases:
        print(f'{case["selected_publication_count"]} publications from {case["base_publication_count"]} to '
              f'{case["publication_count"]}: {case["separate_refreshes"]["median_ms"]:.3f} -> '
              f'{case["batch_refresh"]["median_ms"]:.3f} ms, {case["separate_output_gzip_bytes"]} -> '
              f'{case["batch_output_gzip_bytes"]} bytes, {case["distinct_authorities"]} authorities')


if __name__ == "__main__":
    main()
