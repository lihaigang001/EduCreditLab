"""Compare installed wheels on the same signed chains with alternating block order."""

import argparse
import json
from pathlib import Path
import platform
from statistics import median
import subprocess
import sys

from resolution_refresh_reuse_audit import recheck_receipts
from educreditlab import __version__
from educreditlab.model import read_json, write_json
from educreditlab.resolution_checkpoint import audit_resolution_checkpoint
from educreditlab.transport import gzip_proof, read_proof


BASELINE_VERSION = "1.26.0"
WORKER = Path(__file__).with_name("resolution_refresh_reuse_audit.py").resolve()


def run_block(interpreter, fixture, trials):
    command = [str(interpreter), str(WORKER), "--measure-fixture", str(fixture), "--repeats", str(trials)]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
    return json.loads(result.stdout)


def collect(blocks, version):
    rows = [block["runs"][version] for block in blocks]
    stable = {key: value for key, value in rows[0].items() if key not in ("samples_ms", "median_ms")}
    for row in rows:
        assert all(row[key] == value for key, value in stable.items())
    times = [sample for row in rows for sample in row["samples_ms"]]
    return {**stable, "samples_ms": times, "median_ms": median(times)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--baseline-python", required=True, type=Path,
                        help="Python interpreter with the v1.26.0 wheel installed")
    parser.add_argument("--blocks", default=4, type=int)
    parser.add_argument("--trials-per-block", default=7, type=int)
    args = parser.parse_args()
    if args.blocks < 2 or args.blocks % 2 or args.trials_per_block < 1:
        parser.error("Use an even block count of at least two and a positive trial count")
    args.out_dir.mkdir(parents=True, exist_ok=True)

    baseline, current = BASELINE_VERSION, __version__
    assert baseline != current
    interpreters = {baseline: args.baseline_python.absolute(), current: Path(sys.executable)}
    archives = args.source / "resolution-checkpoint-extension"
    release_pins = read_json(archives / "long/pins.json")
    full = audit_resolution_checkpoint(read_proof(archives / "long/history.json.gz"),
                                       release_pins["initial_authority_sha256"],
                                       release_pins["latest_publication_sha256"])
    cases = []
    for stage_count in (4, 16):
        fixture = (args.source / "resolution-refresh-reuse" / f"{stage_count}-steps").absolute()
        pins = read_json(fixture / "pins.json")
        numbers = pins["expected_publications"]
        canonical = full.batch_witness(numbers)
        assert full.fingerprint == pins["advanced_checkpoint_sha256"]
        assert gzip_proof(canonical) == (fixture / "combined.json.gz").read_bytes()
        blocks = []
        for index in range(args.blocks):
            order = [baseline, current] if index % 2 == 0 else [current, baseline]
            runs = {}
            for version in order:
                row = run_block(interpreters[version], fixture, args.trials_per_block)
                assert row["software_version"] == version
                assert row["signature_batches_checked"] == stage_count and row["matches_full_audit"]
                runs[version] = row
            blocks.append({"order": order, "runs": runs})
            print(f"{stage_count} steps, block {index + 1}: {', '.join(order)}", flush=True)
        old, new = collect(blocks, baseline), collect(blocks, current)
        for key in ("input_gzip_bytes", "proof_gzip_sha256", "proof_gzip_bytes", "verified_publications"):
            assert old[key] == new[key]
        assert new["leaf_hash_calls"] < old["leaf_hash_calls"]
        review = recheck_receipts(args.source, canonical, numbers, full.fingerprint)
        cases.append({"stages": stage_count, "checkpoint_counts": pins["checkpoint_counts"],
                      "baseline": old, "current": new, "blocks": blocks, "receipt_rechecks": [1, 1024]})
        print(f"{stage_count} steps: {old['median_ms']:.3f} to {new['median_ms']:.3f} ms, "
              f"{old['leaf_hash_calls']:,} to {new['leaf_hash_calls']:,} leaf hashes", flush=True)
    write_json(args.out_dir / "measurement.json",
               {"software_version": current, "platform": platform.platform(), "block_count": args.blocks,
                "trials_per_block": args.trials_per_block, "trials_per_version": args.blocks * args.trials_per_block,
                "original_review": review, "cases": cases})


if __name__ == "__main__":
    main()
