"""Measure peak process RSS of installed CLI wheels on the same signed publication history."""

import argparse
from contextlib import redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import platform
from statistics import median
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import perf_counter_ns

from educreditlab import __version__
from educreditlab.model import digest, read_json, write_json


BASELINE_VERSION = "1.27.0"
BASE_COUNT = 31
FINAL_COUNT = 16_415
HANDOVER_NUMBER = 8_192


def prepare_case(results, fixture, case, stage_count, history, full, pins):
    from resolution_refresh_reuse_audit import recheck_receipts
    from educreditlab.resolution_checkpoint import DELTA_KIND, audit_resolution_checkpoint, extend_resolution_checkpoint
    from educreditlab.transport import write_proof

    case.mkdir(parents=True, exist_ok=True)
    publications = history["publications"]
    start_pin = digest(publications[BASE_COUNT - 1]["body"])
    authority = pins["initial_authority_sha256"]
    incoming = publications[HANDOVER_NUMBER - 1]["body"]["successor_authority"]
    assert digest(incoming) == pins["incoming_authority_sha256"]
    prefix = {**history, "publications": publications[:BASE_COUNT]}
    base = audit_resolution_checkpoint(prefix, authority, start_pin)
    head = base.witness()
    write_proof(case / "head.json.gz", head)
    write_proof(case / "source-00.json.gz", base.batch_witness([1, BASE_COUNT]))

    counts = [BASE_COUNT + i * (len(publications) - BASE_COUNT) // stage_count for i in range(stage_count + 1)]
    tips = []
    for i, (start, stop) in enumerate(zip(counts[:-1], counts[1:], strict=True), start=1):
        delta = {"schema": 1, "kind": DELTA_KIND, "base_publication_count": start,
                 "base_publication_sha256": digest(publications[start - 1]["body"]),
                 "base_authority": history["authority"] if start < HANDOVER_NUMBER else incoming,
                 "publications": publications[start:stop]}
        tip = digest(publications[stop - 1]["body"])
        head = extend_resolution_checkpoint(head, delta, digest(head["checkpoint"]), tip)
        tips.append(tip)
        write_proof(case / f"step-{i:02}.json.gz", delta)
        write_proof(case / f"source-{i:02}.json.gz", head)
    assert head == full.witness() and tips[-1] == pins["latest_publication_sha256"]
    new = [HANDOVER_NUMBER, FINAL_COUNT - 1]
    numbers = sorted({1, *counts, *new})
    canonical = full.batch_witness(numbers)
    write_proof(case / "combined.json.gz", canonical)
    write_json(case / "pins.json", {
        "base_checkpoint_sha256": base.fingerprint, "final_checkpoint_sha256": full.fingerprint,
        "stage_publication_sha256": tips, "checkpoint_counts": counts,
        "expected_publications": numbers, "expected_new_publications": new,
    })
    return recheck_receipts(results, canonical, numbers, full.fingerprint, signed=fixture,
                            endpoints=fixture / "long/endpoints.json", incoming_number=HANDOVER_NUMBER)


def peak_rss_kib():
    with Path("/proc/self/status").open(encoding="ascii") as status:
        for line in status:
            key, _, value = line.partition(":")
            if key == "VmHWM":
                amount, unit = value.split()
                assert unit == "kB"
                return int(amount)
    raise RuntimeError("Cannot read the process peak RSS")


def measure_cli(case):
    from educreditlab.cli import main as run

    pins = read_json(case / "pins.json")
    tips = pins["stage_publication_sha256"]
    args = ["resolution-history", "checkpoint-chain-merge-batch", str(case / "head.json.gz")]
    args.extend(str(case / f"source-{i:02}.json.gz") for i in range(len(tips) + 1))
    args.extend(("--publication-checkpoint-trust", pins["base_checkpoint_sha256"]))
    for i, tip in enumerate(tips, start=1):
        args.extend(("--step", str(case / f"step-{i:02}.json.gz"), tip))
    for number in pins["expected_publications"]:
        args.extend(("--publication", str(number)))
    for number in pins["expected_new_publications"]:
        args.extend(("--include-new-publication", str(number)))

    with TemporaryDirectory() as temp:
        output = Path(temp) / "combined.json.gz"
        args.extend(("--out", str(output)))
        startup_peak = peak_rss_kib()
        start = perf_counter_ns()
        with redirect_stdout(StringIO()) as stdout:
            status = run(args)
        elapsed_ms = (perf_counter_ns() - start) / 1_000_000
        peak = peak_rss_kib()
        assert status == 0
        result = json.loads(stdout.getvalue())
        assert result["publications"] == pins["expected_publications"]
        assert result["publication_checkpoint_sha256"] == pins["final_checkpoint_sha256"]
        wire = output.read_bytes()
        assert wire == (case / "combined.json.gz").read_bytes()
    return {"software_version": __version__, "python": platform.python_version(),
            "startup_peak_rss_kib": startup_peak, "peak_rss_kib": peak, "elapsed_ms": elapsed_ms,
            "proof_gzip_sha256": sha256(wire).hexdigest(), "matches_full_audit": True}


def compare(case, baseline_python, repeats):
    interpreters = {BASELINE_VERSION: baseline_python.absolute(), __version__: Path(sys.executable)}
    pins = read_json(case / "pins.json")
    canonical_sha = sha256((case / "combined.json.gz").read_bytes()).hexdigest()
    runs = []
    for i in range(repeats):
        order = list(interpreters) if i % 2 == 0 else list(reversed(interpreters))
        rows = []
        for version in order:
            command = [str(interpreters[version]), str(Path(__file__).resolve()), "--worker", str(case.absolute())]
            trial = subprocess.run(command, check=True, text=True, capture_output=True, timeout=120)
            row = json.loads(trial.stdout)
            assert row["software_version"] == version
            assert row["proof_gzip_sha256"] == canonical_sha and row["matches_full_audit"]
            rows.append(row)
        runs.append(rows)
        print(f"{len(pins['stage_publication_sha256'])} steps, pair {i + 1}/{repeats}: "
              + ", ".join(f"{row['software_version']} {row['peak_rss_kib']} KiB" for row in rows), flush=True)
    counts = pins["checkpoint_counts"]
    summaries = {}
    for version in interpreters:
        samples = [row for pair in runs for row in pair if row["software_version"] == version]
        summaries[version] = {field: median(row[field] for row in samples)
                              for field in ("startup_peak_rss_kib", "peak_rss_kib", "elapsed_ms")}
    return {"stages": len(counts) - 1, "checkpoint_counts": counts,
            "max_stage_publications": max(stop - start for start, stop in zip(counts[:-1], counts[1:], strict=True)),
            "proof_gzip_sha256": canonical_sha, "verified_publications": len(pins["expected_publications"]),
            "receipt_rechecks": [1, HANDOVER_NUMBER], "median_by_version": summaries, "trials": runs}


def main():
    from educreditlab.resolution_checkpoint import audit_resolution_checkpoint
    from educreditlab.transport import read_proof

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("results"))
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--baseline-python", type=Path, help="Interpreter with the v1.27.0 wheel installed")
    parser.add_argument("--pairs", type=int, default=6)
    parser.add_argument("--generate-fixture", type=Path, help="Create a new synthetic signed history at this path")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("Peak RSS measurement requires Linux /proc")
    if args.worker:
        print(json.dumps(measure_cli(args.worker)))
        return
    if args.out_dir is None or args.baseline_python is None or args.pairs < 2 or args.pairs % 2:
        parser.error("Use --out-dir, --baseline-python and an even number of trial pairs")
    if __version__ == BASELINE_VERSION:
        parser.error("Run the comparison using the current wheel")

    fixture = args.source / "resolution-chain-memory/fixture"
    if args.generate_fixture is not None:
        from resolution_checkpoint_extension_audit import generate

        fixture = args.generate_fixture
        fixture.mkdir(parents=True, exist_ok=True)
        if any(fixture.iterdir()):
            parser.error("Use an empty directory to generate a synthetic fixture")
        generate(args.source, fixture, prefix_sizes={"long": HANDOVER_NUMBER - 1},
                 new_publications=FINAL_COUNT - HANDOVER_NUMBER + 1)
    history_path = fixture / "long/history.json.gz"
    history = read_proof(history_path)
    assert len(history["publications"]) == FINAL_COUNT
    pins = read_json(fixture / "long/endpoints.json")
    full = audit_resolution_checkpoint(history, pins["initial_authority_sha256"], pins["latest_publication_sha256"])
    cases = []
    reviews = []
    for stages in (4, 16):
        case = args.out_dir / f"{stages}-steps"
        reviews.append(prepare_case(args.source, fixture, case, stages, history, full, pins))
        cases.append(compare(case, args.baseline_python, args.pairs))
    assert reviews[0] == reviews[1]
    write_json(args.out_dir / "measurement.json", {
        "software_version": __version__, "baseline_version": BASELINE_VERSION, "platform": platform.platform(),
        "pairs_per_case": args.pairs, "history_gzip_sha256": sha256(history_path.read_bytes()).hexdigest(),
        "original_review": reviews[0], "cases": cases,
    })


if __name__ == "__main__":
    main()
