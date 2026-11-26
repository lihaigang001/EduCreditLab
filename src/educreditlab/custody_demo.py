"""Reproducible synthetic example of institution and validator key rotation."""

from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__, custody
from .keys import KeyRegistry, enroll
from .lab import DEMO_ACTORS, bundled_data, verify_review
from .ledger import MODES, head_document
from .model import LabError, write_json, write_text


def run_demo(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="educreditlab-custody-") as directory:
        root = Path(directory)
        actors = {name: Ed25519PrivateKey.generate() for name in DEMO_ACTORS}
        validators = {name: Ed25519PrivateKey.generate() for name in MODES["consortium"][0]}
        lab = custody.initialize(root / "coordinator", [
            enroll(role, name, key) for role, group in (("actor", actors), ("validator", validators))
            for name, key in group.items()
        ])
        ledger, fingerprint = lab.ledger, lab.ledger.fingerprint

        def head():
            return head_document(ledger.manifest, ledger.prefix())

        nodes = {name: custody.ValidatorStore(root / f"{name}.sqlite3", name, fingerprint)
                 for name in validators}
        for node in nodes.values():
            node.initialize(head())

        def commit(operation, members):
            request = custody.submit(lab, operation)["request"]
            votes = [nodes[name].vote(request, validators[name]) for name in members]
            return ledger.commit_external(votes)

        first = ("peer-a", "peer-b", "peer-c")
        later = ("peer-b", "peer-c", "peer-d")
        for policy in bundled_data("policies.json"):
            operation = custody.sign_policy(head(), fingerprint, policy, actors[policy["receiver"]])
            commit(operation, first)

        transcript = bundled_data("cases.json")[0]["transcript"]
        signed = custody.sign_transcript(head(), fingerprint, transcript, actors[transcript["issuer"]])
        target = ("uc-irvine", "cse-bs", "2023-06-15")
        request = custody.prepare_receipt(lab, signed, *target, known_height=3)
        before = custody.submit(lab, custody.approve_receipt(request, fingerprint, actors["uc-irvine"]))
        votes = [nodes[name].vote(before["request"], validators[name]) for name in first]
        try:
            ledger.commit_external(votes[:2])
        except LabError as exc:
            if "quorum" not in str(exc).lower() or ledger.pending_height() != before["height"]:
                raise
        else:
            raise LabError("The demonstration committed without its voting quorum")
        old_block = ledger.commit_external(votes)

        for role, name, owners in (("actor", "uc-irvine", actors), ("validator", "peer-b", validators)):
            replacement = Ed25519PrivateKey.generate()
            commit(custody.authorize_rotation(head(), fingerprint, role, name, owners[name], replacement,
                                              "Synthetic scheduled renewal"), first)
            owners[name] = replacement

        request = custody.prepare_receipt(lab, signed, *target, known_height=3)
        new_block = commit(custody.approve_receipt(request, fingerprint, actors["uc-irvine"]), later)
        evidence = []
        for label, block in (("before", old_block), ("after", new_block)):
            commitment = block["core"]["event"]["body"]["payload"]["receipt_sha256"]
            proof = lab.bundle(commitment)
            checked = verify_review(proof, fingerprint)
            if checked["decision"]["recognized_units"] != 1600:
                raise LabError("The demonstration decision changed during key rotation")
            write_json(output / f"proof-{label}-rotation.json", proof)
            evidence.append({"height": checked["height"], "receipt_sha256": commitment,
                             "recognized_units": checked["decision"]["recognized_units"],
                             "unit": checked["decision"]["unit"], "validators": sorted(block["votes"]),
                             "knowledge_height": checked["policy_view"]["knowledge"]["height"],
                             "replayed": checked["replayed"]})
        results = {"software_version": __version__, "synthetic": True, "manifest_sha256": fingerprint,
                   "assessment_date": target[-1], "two_votes_kept_proposal_pending": True,
                   "rotations": KeyRegistry(ledger.manifest, ledger.prefix()).rotations,
                   "receipts": evidence}
        write_json(output / "custody-summary.json", results)
        write_text(output / "trusted-manifest-sha256.txt", fingerprint + "\n")
        return results
