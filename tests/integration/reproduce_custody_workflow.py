"""Run the public CLI through isolated working directories using synthetic files."""

import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from secrets import token_urlsafe

from educreditlab.lab import DEMO_ACTORS, bundled_data
from educreditlab.model import read_json, write_json

if len(sys.argv) != 2:
    raise SystemExit("Usage: python tests/integration/reproduce_custody_workflow.py NEW_DIRECTORY")
root = Path(sys.argv[1]).resolve()
root.mkdir(mode=0o700)
coordinator = root / "coordinator"
coordinator.mkdir(mode=0o700)
names = ("peer-a", "peer-b", "peer-c", "peer-d")
owner = {name: root / name for name in (*DEMO_ACTORS, *names)}
passwords = {name: token_urlsafe(36) for name in owner}
operations = 0


def cli(directory, *arguments, passwords=None, failure=None):
    global operations
    operations += 1
    request = None if passwords is None else "\n".join((*passwords, ""))
    result = subprocess.run([sys.executable, "-m", "educreditlab", *map(str, arguments)],
                            cwd=directory, input=request, encoding="utf-8", capture_output=True, check=False)
    if failure is not None:
        assert result.returncode == 2 and failure in result.stderr, (arguments, result.stderr)
        return None
    assert result.returncode == 0, (arguments, result.stderr)
    return json.loads(result.stdout)


enrollments = []
for name, directory in owner.items():
    directory.mkdir(mode=0o700)
    cli(directory, "custody", "keygen", "validator" if name in names else "actor", name,
        "--key", "key.pem", "--enrollment", "enrollment.json", "--passphrase-stdin", passwords=[passwords[name]])
    enrollment = f"enrollment-{name}.json"
    shutil.copyfile(directory / "enrollment.json", coordinator / enrollment)
    enrollments.append(enrollment)


def central(*args, **kwargs):
    return cli(coordinator, "--workspace", "network", "custody", *args, **kwargs)


root_manifest = central("init", *enrollments, "--out", "head.json")
trust = root_manifest["trust_fingerprint"]
for name in names:
    shutil.copyfile(coordinator / "head.json", owner[name] / "genesis.json")
    cli(owner[name], "custody", "validator-init", "genesis.json", "--validator", name,
        "--state", "votes.db", "--trust", trust)


def transmit_head(name):
    shutil.copyfile(coordinator / "head.json", owner[name] / "head.json")


def submit(name, filename):
    shutil.copyfile(owner[name] / filename, coordinator / "operation.json")
    return central("submit", "operation.json", "--out", "proposal.json")


def endorse(members, active_validator_key):
    votes = []
    for name in members:
        reply = f"vote-{name}.json"
        shutil.copyfile(coordinator / "proposal.json", owner[name] / "proposal.json")
        path = active_validator_key if name == "peer-b" else "key.pem"
        cli(owner[name], "custody", "vote", "proposal.json", "--validator", name, "--state", "votes.db",
            "--key", path, "--trust", trust, "--out", reply, "--passphrase-stdin", passwords=[passwords[name]])
        shutil.copyfile(owner[name] / reply, coordinator / reply)
        votes.append(reply)
    return votes


base = ("peer-a", "peer-b", "peer-c")
for policy in bundled_data("policies.json"):
    receiver = policy["receiver"]
    write_json(owner[receiver] / "policy.json", policy)
    transmit_head(receiver)
    cli(owner[receiver], "custody", "sign-policy", "policy.json", "--head", "head.json", "--key", "key.pem",
        "--trust", trust, "--out", "policy-signed.json", "--passphrase-stdin", passwords=[passwords[receiver]])
    submit(receiver, "policy-signed.json")
    central("commit", *endorse(base, "key.pem"), "--out", "head.json")

transcript = bundled_data("cases.json")[0]["transcript"]
sender, receiver = transcript["issuer"], "uc-irvine"
write_json(owner[sender] / "transcript.json", transcript)
transmit_head(sender)
cli(owner[sender], "custody", "sign-transcript", "transcript.json", "--head", "head.json", "--key", "key.pem",
    "--trust", trust, "--out", "approved-transcript.json", "--passphrase-stdin", passwords=[passwords[sender]])
shutil.copyfile(owner[sender] / "approved-transcript.json", coordinator / "approved-transcript.json")


def approve(key_file):
    central("prepare-receipt", "approved-transcript.json", "--receiver", receiver, "--as-of", "2023-06-15",
            "--known-height", 3, "--out", "request.json")
    shutil.copyfile(coordinator / "request.json", owner[receiver] / "request.json")
    result = cli(owner[receiver], "custody", "approve-receipt", "request.json", "--key", key_file,
                 "--trust", trust, "--out", "receipt.json", "--passphrase-stdin", passwords=[passwords[receiver]])
    assert result["recognized_units"] == 1600
    submit(receiver, "receipt.json")
    proposal = (coordinator / "proposal.json").read_text()
    assert '"transcript"' not in proposal and '"attempts"' not in proposal and '"decision"' not in proposal
    return result["receipt_sha256"]


before = approve("key.pem")
votes = endorse(base, "key.pem")
central("commit", *votes[:2], "--out", "head.json", failure="quorum")
central("pending", "--out", "recovered.json")
assert read_json(coordinator / "recovered.json") == read_json(coordinator / "proposal.json")
assert central("commit", *votes, "--out", "head.json")["height"] == 4

for role, name in (("actor", receiver), ("validator", "peer-b")):
    transmit_head(name)
    cli(owner[name], "custody", "keygen", role, name, "--key", "next.pem", "--enrollment", "next.json",
        "--passphrase-stdin", passwords=[passwords[name]])
    cli(owner[name], "custody", "rotate", role, name, "--head", "head.json", "--trust", trust,
        "--old-key", "key.pem", "--new-key", "next.pem", "--reason", "Scheduled test renewal",
        "--out", "rotation.json", "--passphrase-stdin", passwords=[passwords[name], passwords[name]])
    submit(name, "rotation.json")
    central("commit", *endorse(base, "key.pem"), "--out", "head.json")

after = approve("next.pem")
final = central("commit", *endorse(("peer-b", "peer-c", "peer-d"), "next.pem"), "--out", "head.json")
assert final["height"] == 7
for name in names:
    transmit_head(name)
    status = cli(owner[name], "custody", "validator-sync", "head.json", "--validator", name,
                 "--state", "votes.db", "--trust", trust)
    assert status["height"] == 7

for label, receipt in (("before", before), ("after", after)):
    path = f"proof-{label}.json"
    cli(coordinator, "--workspace", "network", "bundle", receipt, "--out", path)
    result = cli(root, "verify", coordinator / path, "--trust", trust)
    assert result["replayed"] and result["decision"]["recognized_units"] == 1600
    assert result["height"] == (4 if label == "before" else 7)
    assert result["policy_view"]["knowledge"]["height"] == 3

with sqlite3.connect(coordinator / "network/ledger.sqlite3") as connection:
    assert json.loads(connection.execute("SELECT keys FROM settings").fetchone()[0]) == {"actors": {}, "validators": {}}
assert not list(coordinator.rglob("*.pem"))
print(f"PASS {operations} CLI process launches, seven owner directories, quorum restart, two key rotations, four independent validator stores, two offline proofs")
