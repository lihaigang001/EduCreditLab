"""Measure individual compact proofs and a shared multiproof for identical receipt sets."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
import platform

from checkpoint_audit import time_trials
from long_history_audit import build
from educreditlab import __version__
from educreditlab.checkpoint import audit_checkpoint, workspace_checkpoint
from educreditlab.lab import Lab, verify_review
from educreditlab.model import read_json, write_bytes, write_json
from educreditlab.transport import decode_proof, gzip_proof


def measure(fixture, output, counts, repeats):
    root = Path(fixture)
    lab = Lab.open(root / "state")
    exported, archive = workspace_checkpoint(lab.ledger)
    trust = read_json(root / "fixture.json")["manifest_sha256"]
    index = audit_checkpoint(archive, trust)
    checkpoint = index.fingerprint
    if exported.descriptor != index.descriptor:
        raise ValueError("Workspace and independent checkpoint audits disagree")
    candidates = [
        (block["core"]["height"], event["payload"]["receipt_sha256"])
        for block in archive["chain"]
        if (event := block["core"]["event"]["body"])["kind"] == "receipt"
    ]
    if max(counts) > len(candidates):
        raise ValueError("The requested batch exceeds the number of certified receipts in the fixture")

    def verify(document, **options):
        return verify_review(document, trust, trusted_checkpoint=checkpoint, **options)

    cases = []
    for size in counts:
        picks = [candidates[i * (len(candidates) - 1) // max(1, size - 1)] for i in range(size)]
        heights, refs = map(list, zip(*picks))
        evidence = {ref: lab.ledger.artifact(ref, "receipt") for ref in refs}
        individual = [index.proof(ref, evidence[ref]) for ref in refs]
        batch = index.batch_proof(refs, evidence)
        single_bytes = [gzip_proof(proof) for proof in individual]
        batch_bytes = gzip_proof(batch)
        independent, single_time = time_trials(lambda: [verify(decode_proof(data)) for data in single_bytes], repeats)
        shared, batch_time = time_trials(lambda: verify(decode_proof(batch_bytes), expected_receipts=refs), repeats)
        common = {key: shared[key] for key in ("manifest_sha256", "checkpoint_sha256", "checkpoint_height", "quorum", "mode")}
        if independent != [{**common, **row} for row in shared["receipts"]]:
            raise ValueError("Batched replay differs from the independently verified receipts")
        cases.append({
            "receipt_count": size, "receipt_heights": heights,
            "individual_gzip_bytes": sum(map(len, single_bytes)),
            "array_gzip_bytes": len(gzip_proof(individual)), "batch_gzip_bytes": len(batch_bytes),
            "individual_path_hashes": sum(len(p["receipt_witness"]["path"]) + len(p["scope_witness"]["path"])
                                          for p in individual),
            "batch_sibling_hashes": len(batch["siblings"]), "shared_policy_count": len(batch["policies"]),
            "individual_verify": single_time, "batch_verify": batch_time, "same_receipt_results": True,
        })
        print(f"{size} receipts: {cases[-1]['individual_gzip_bytes']:,} individual bytes, "
              f"{cases[-1]['array_gzip_bytes']:,} array bytes, {len(batch_bytes):,} batch bytes", flush=True)
        if size == max(counts):
            anchor = index.batch_proof(refs)
            verified = verify(anchor, expected_receipts=refs)
            if not all(row["anchor_verified"] and not row["replayed"] for row in verified["receipts"]):
                raise ValueError("A batch anchor could not be verified")
            write_bytes(output / "full-batch.json.gz", batch_bytes)
            write_bytes(output / "anchor-batch.json.gz", gzip_proof(anchor))
            write_json(output / "expected-receipts.json", refs)
    return {
        "software_version": __version__, "platform": platform.platform(), "python": platform.python_version(),
        "checkpoint": index.descriptor, "checkpoint_sha256": checkpoint, "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", help="Existing synthetic workspace produced by long_history_audit.py")
    parser.add_argument("--height", type=int, default=10000, help="Block count when generating a synthetic workspace")
    parser.add_argument("--counts", nargs="+", type=int, default=[8, 32, 128])
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    if args.repeats < 1 or min(args.counts) < 1 or len(set(args.counts)) != len(args.counts):
        parser.error("Use positive trial counts and distinct positive batch sizes")
    if not args.fixture and args.height < max(args.counts) + 3:
        parser.error("The synthetic history needs at least three policy blocks and the largest batch size")
    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    if args.fixture:
        result = measure(args.fixture, output, args.counts, args.repeats)
    else:
        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "history"
            build(fixture, args.height)
            result = measure(fixture, output, args.counts, args.repeats)
    write_json(output / "measurement.json", result)


if __name__ == "__main__":
    main()
