"""Compare installed wheels on signed checkpoint chains and count hashing separately."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import subprocess
from unittest.mock import patch

from checkpoint_audit import time_trials
from educreditlab import __version__, merkle, resolution_checkpoint
from educreditlab.model import digest, read_json, write_json
from educreditlab.resolution_checkpoint import (
    advance_chain_and_merge_resolution_witnesses, audit_resolution_checkpoint,
    resolution_checkpoint_delta, verify_checkpoint_batch_resolution, verify_resolution_batch,
)
from educreditlab.transport import decode_proof, gzip_proof, read_proof, write_proof


def prepare(source, destination, steps):
    archives = source / "resolution-checkpoint-extension"
    pins = read_json(archives / "long/pins.json")
    authority, tip = pins["initial_authority_sha256"], pins["latest_publication_sha256"]
    history = read_proof(archives / "long/history.json.gz")
    publications = history["publications"]
    base_size, final_size = 31, len(publications)
    counts = [base_size + i * (final_size - base_size) // steps for i in range(steps + 1)]
    destination.mkdir(parents=True, exist_ok=True)
    heads = []
    for i, count in enumerate(counts):
        prefix = {**history, "publications": publications[:count]}
        expected = digest(publications[count - 1]["body"])
        index = audit_resolution_checkpoint(prefix, authority, expected)
        write_proof(destination / f"source-{i:02}.json.gz", index.batch_witness([1, count]))
        if i == 0:
            write_proof(destination / "head.json.gz", index.witness())
            base = index.fingerprint
        else:
            delta = resolution_checkpoint_delta(prefix, authority, expected, from_number=counts[i - 1])
            write_proof(destination / f"step-{i:02}.json.gz", delta)
            heads.append(expected)
    assert heads[-1] == tip and index.fingerprint == pins["advanced_checkpoint_sha256"]
    new_publications = [1024, 1030]
    numbers = sorted({1, *counts, *new_publications})
    canonical = index.batch_witness(numbers)
    write_proof(destination / "combined.json.gz", canonical)
    write_json(destination / "pins.json", {
        "base_checkpoint_sha256": base, "advanced_checkpoint_sha256": index.fingerprint,
        "stage_publication_sha256": heads, "checkpoint_counts": counts, "expected_publications": numbers,
        "expected_new_publications": new_publications, "initial_authority_sha256": authority,
        "incoming_authority_sha256": pins["incoming_authority_sha256"],
    })
    return canonical, numbers, index.fingerprint


def measure(fixture, repeats):
    pins = read_json(fixture / "pins.json")
    step_count = len(pins["stage_publication_sha256"])
    head = (fixture / "head.json.gz").read_bytes()
    steps = [(fixture / f"step-{i:02}.json.gz").read_bytes() for i in range(1, step_count + 1)]
    sources = [(fixture / f"source-{i:02}.json.gz").read_bytes() for i in range(step_count + 1)]
    expected = (fixture / "combined.json.gz").read_bytes()
    numbers = pins["expected_publications"]

    def operation():
        return advance_chain_and_merge_resolution_witnesses(
            decode_proof(head), [decode_proof(step) for step in steps], [decode_proof(source) for source in sources],
            pins["base_checkpoint_sha256"], pins["stage_publication_sha256"], numbers=numbers,
            new_publications=pins["expected_new_publications"])

    assert gzip_proof(operation()) == expected
    proof, timings = time_trials(operation, repeats)
    packed = gzip_proof(proof)
    checked = verify_resolution_batch(proof, pins["advanced_checkpoint_sha256"], numbers=numbers)
    assert packed == expected
    leaf_calls, refresh_leaf_calls, signature_batches = 0, 0, 0
    leaf, refresh = merkle._leaf, resolution_checkpoint._refresh_verified_batch
    verify = resolution_checkpoint._verify_publications

    def count_leaf(entry):
        nonlocal leaf_calls
        leaf_calls += 1
        return leaf(entry)

    def count_refresh(*args, **kwargs):
        nonlocal refresh_leaf_calls
        before = leaf_calls
        result = refresh(*args, **kwargs)
        refresh_leaf_calls += leaf_calls - before
        return result

    def count_signatures(*args, **kwargs):
        nonlocal signature_batches
        signature_batches += 1
        return verify(*args, **kwargs)

    with patch.object(merkle, "_leaf", count_leaf), patch.object(
            resolution_checkpoint, "_refresh_verified_batch", count_refresh), patch.object(
            resolution_checkpoint, "_verify_publications", count_signatures):
        assert operation() == proof
    assert signature_batches == step_count
    return {"software_version": __version__, "python": platform.python_version(), **timings,
            "leaf_hash_calls": leaf_calls, "refresh_leaf_hash_calls": refresh_leaf_calls,
            "signature_batches_checked": signature_batches, "input_gzip_bytes": sum(map(len, [head, *steps, *sources])),
            "proof_gzip_sha256": sha256(packed).hexdigest(), "proof_gzip_bytes": len(packed),
            "verified_publications": len(checked["verified_publications"]), "matches_full_audit": True}


def recheck_receipts(source, proof, numbers, checkpoint, *, signed=None, endpoints=None, incoming_number=1024):
    signed = source / "resolution-checkpoint-extension" if signed is None else signed
    pins = read_json(signed / "long/pins.json" if endpoints is None else endpoints)
    earlier = json.loads((source / "resolution-checkpoint-chain/measurement.json").read_text(encoding="utf-8"))
    review = earlier["original_review"]
    original = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(original) == review["proof_sha256"]
    for number, role, branch, key in (
            (1, "outgoing", "left", "initial_authority_sha256"),
            (incoming_number, "incoming", "right", "incoming_authority_sha256")):
        verdict = verify_checkpoint_batch_resolution(
            proof, read_proof(signed / f"{role}-resolution.json.gz"), checkpoint, numbers=numbers, number=number,
            bundle=read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz"), proof=original,
            trusted_manifest=review["manifest_sha256"], trusted_checkpoint=review["checkpoint_sha256"],
            expected_proof=review["proof_sha256"])
        assert verdict["proof_rechecked"] and verdict["verified_authority_sha256"] == pins[key]
        for field in ("result_sha256", "receipt_count", "replay_count", "anchor_count"):
            assert verdict[field] == review[field]
    return review


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--baseline-python", type=Path, help="Interpreter with the v1.25.0 wheel installed")
    parser.add_argument("--repeats", type=int, default=21)
    parser.add_argument("--measure-fixture", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    if args.measure_fixture:
        print(json.dumps(measure(args.measure_fixture, args.repeats)))
        return
    if args.out_dir is None:
        parser.error("Use --out-dir to save the fixtures and results")
    cases = []
    for steps in (4, 16):
        fixture = args.out_dir / f"{steps}-steps"
        proof, numbers, checkpoint = prepare(args.source, fixture, steps)
        baseline = None
        if args.baseline_python is not None:
            outcome = subprocess.run(
                [args.baseline_python.absolute(), Path(__file__).resolve(), "--measure-fixture", fixture,
                 "--repeats", str(args.repeats)], check=True, capture_output=True, text=True, timeout=120)
            baseline = json.loads(outcome.stdout)
            assert baseline["software_version"] == "1.25.0"
        current = measure(fixture, args.repeats)
        if baseline is not None:
            assert baseline["input_gzip_bytes"] == current["input_gzip_bytes"]
            assert baseline["proof_gzip_sha256"] == current["proof_gzip_sha256"]
        review = recheck_receipts(args.source, proof, numbers, checkpoint)
        cases.append({"stages": steps, "checkpoints": steps + 1, "base_publications": 31, "final_publications": 1031,
                      "baseline": baseline, "current": current, "receipt_rechecks": [1, 1024]})
        print(f"{steps} steps: {current['verified_publications']} verified publications, "
              f"{current['refresh_leaf_hash_calls']:,} refresh leaf hashes, {current['median_ms']:.3f} ms.", flush=True)
    write_json(args.out_dir / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                                   "repeats": args.repeats, "original_review": review, "cases": cases})


if __name__ == "__main__":
    main()
