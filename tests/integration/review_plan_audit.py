"""Measure one plan-bound proof and equivalent uniform proofs at the same checkpoint."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
import platform

from checkpoint_audit import time_trials
from long_history_audit import build
from educreditlab import __version__
from educreditlab.checkpoint import audit_checkpoint, workspace_checkpoint
from educreditlab.lab import Lab, verify_review
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.review_plan import make_review_plan
from educreditlab.transport import decode_proof, gzip_proof

GROUP_SIZE = 128
REPLAY_COUNTS = (0, 16, 64, GROUP_SIZE)


def measure(fixture, output, repeats):
    root = Path(fixture)
    lab = Lab.open(root / "state")
    exported, archive = workspace_checkpoint(lab.ledger)
    trust = read_json(root / "fixture.json")["manifest_sha256"]
    index = audit_checkpoint(archive, trust)
    checkpoint = index.fingerprint
    if index.descriptor != exported.descriptor:
        raise ValueError("Workspace and independent checkpoint audits disagree")
    available = [event["payload"]["receipt_sha256"] for block in archive["chain"]
                 if (event := block["core"]["event"]["body"])["kind"] == "receipt"]
    if len(available) < GROUP_SIZE:
        raise ValueError("The fixture must supply at least 128 certified receipts")
    references = [available[i * (len(available) - 1) // (GROUP_SIZE - 1)] for i in range(GROUP_SIZE)]

    def evidence_for(reference):
        return lab.ledger.artifact(reference, "receipt")

    def verify_uniform(groups):
        rows = []
        for data, group in groups:
            checked = verify_review(decode_proof(data), trust, trusted_checkpoint=checkpoint,
                                    expected_receipts=group)
            rows.extend(checked["receipts"])
        return sorted(rows, key=lambda row: row["height"])

    cases = []
    for count in REPLAY_COUNTS:
        selected = {i * (GROUP_SIZE - 1) // max(1, count - 1) for i in range(count)}
        replay = [ref for i, ref in enumerate(references) if i in selected]
        anchors = [ref for i, ref in enumerate(references) if i not in selected]
        groups = []
        if replay:
            full = index.batch_proof(replay, {ref: evidence_for(ref) for ref in replay})
            groups.append((gzip_proof(full), replay))
        if anchors:
            groups.append((gzip_proof(index.batch_proof(anchors)), anchors))
        plan = make_review_plan(trust, checkpoint, replay=replay, anchor=anchors)
        pin = digest(plan)
        proof = index.review_proof(plan, pin, evidence_for)
        encoded = gzip_proof(proof)
        paired, uniform_timing = time_trials(lambda: verify_uniform(groups), repeats)
        merged, plan_timing = time_trials(
            lambda: verify_review(decode_proof(encoded), trust, trusted_checkpoint=checkpoint,
                                  trusted_plan=pin), repeats)
        if (set(proof["evidence"]) != set(replay) or merged["replay_count"] != count
                or merged["anchor_count"] != len(anchors) or merged["receipts"] != paired):
            raise ValueError("Planned disclosure or replay differs from the matched controls")
        cases.append({
            "replay_count": count, "anchor_count": len(anchors), "attached_evidence_count": len(proof["evidence"]),
            "uniform_gzip_bytes": sum(len(data) for data, _ in groups), "uniform_files": len(groups),
            "planned_gzip_bytes": len(encoded), "review_plan_sha256": pin, "same_receipt_results": True,
            "uniform_verify": uniform_timing, "planned_verify": plan_timing,
        })
        print(f"{count} replays: {cases[-1]['uniform_gzip_bytes']:,} uniform bytes, {len(encoded):,} planned bytes",
              flush=True)
        if count == 16:
            write_json(output / "plan.json", plan)
            write_bytes(output / "review-128.json.gz", encoded)
    return {"software_version": __version__, "platform": platform.platform(), "python": platform.python_version(),
            "checkpoint": index.descriptor, "checkpoint_sha256": checkpoint,
            "receipt_count": GROUP_SIZE, "cases": cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", help="A synthetic workspace created with long_history_audit.py")
    parser.add_argument("--height", type=int, default=10000, help="Block count for a newly generated fixture")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    if args.repeats < 1 or (not args.fixture and args.height < GROUP_SIZE + 3):
        parser.error("Use a positive repeat count and at least 131 blocks when generating a fixture")
    output = Path(args.out_dir)
    output.mkdir(parents=True, exist_ok=True)
    if args.fixture:
        result = measure(args.fixture, output, args.repeats)
    else:
        with TemporaryDirectory() as directory:
            fixture = Path(directory) / "history"
            build(fixture, args.height)
            result = measure(fixture, output, args.repeats)
    write_json(output / "measurement.json", result)


if __name__ == "__main__":
    main()
