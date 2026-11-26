from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from itertools import product
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from educreditlab.cli import main
from educreditlab.merkle import MerkleTree
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (BATCH_KIND, CHECKPOINT_KIND, WITNESS_KIND, audit_resolution_checkpoint,
                                               merge_resolution_witnesses, refresh_resolution_batch, select_resolution_witness,
                                               verify_checkpoint_batch_resolution, verify_resolution_batch)
from educreditlab.transport import read_proof, write_proof


class ResolutionMergeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.handover = cls.results / "resolution-batch/handover"
        cls.mixed = cls.results / "resolution-batch/mixed"
        cls.archive = cls.results / "resolution-checkpoint-extension"
        cls.pins = read_json(cls.handover / "pins.json")
        cls.source = read_proof(cls.handover / "refreshed-batch.json.gz")
        cls.numbers = cls.pins["expected_publications"]
        cls.trust = cls.pins["advanced_checkpoint_sha256"]
        cls.index = audit_resolution_checkpoint(read_proof(cls.archive / "short/history.json.gz"),
                                                cls.pins["initial_authority_sha256"], cls.pins["latest_publication_sha256"])

    def project(self, ordinals, *, single=False):
        return select_resolution_witness(self.source, self.trust, numbers=self.numbers, selected=ordinals, single=single)

    def test_all_nonempty_pairs_in_small_trees_match_full_union_proof(self):
        for size in range(1, 6):
            entries = [{"number": number, "publication_sha256": digest(["pub", number]),
                        "decision_sha256": digest(["decision", number]), "authority_sha256": digest("authority")}
                       for number in range(1, size + 1)]
            tree = MerkleTree(entries)
            descriptor = {"schema": 1, "kind": CHECKPOINT_KIND, "publication_count": size,
                          "history_sha256": digest("history"), "initial_authority_sha256": digest("authority"),
                          "divergence_sha256": digest("divergence"), "latest_publication_sha256": entries[-1]["publication_sha256"],
                          "merkle_root": tree.root}
            trusted = digest(descriptor)
            subsets = {}
            for mask in range(1, 1 << size):
                indices = [index for index in range(size) if mask & (1 << index)]
                selected = [entries[index] for index in indices]
                if len(indices) == 1:
                    witness = {"schema": 1, "kind": WITNESS_KIND, "checkpoint": descriptor,
                               "entry": selected[0], "siblings": tree.path(indices[0])}
                else:
                    witness = {"schema": 1, "kind": BATCH_KIND, "checkpoint": descriptor,
                               "entries": selected, "siblings": tree.multipath(indices)}
                subsets[mask] = witness
            for left, right in product(subsets, repeat=2):
                indices = [index for index in range(size) if (left | right) & (1 << index)]
                combined = merge_resolution_witnesses([subsets[left], subsets[right]], trusted,
                                                       numbers=[i + 1 for i in indices])
                self.assertEqual(combined["entries"], [entries[i] for i in indices])
                self.assertEqual(combined["siblings"], tree.multipath(indices))

    def test_single_and_overlapping_batches_are_canonical_after_deduplication(self):
        sources = [self.project([1, 5, 31]), self.project([5, 17]), self.project([21], single=True)]
        target = [1, 5, 17, 21, 31]
        merged = merge_resolution_witnesses(sources, self.trust, numbers=target)
        self.assertEqual(merged, self.index.batch_witness(target))
        self.assertEqual(merged, merge_resolution_witnesses(list(reversed(sources)), self.trust, numbers=target[::-1]))
        result = verify_resolution_batch(merged, self.trust, numbers=target)
        self.assertEqual([entry["verified_publication"] for entry in result["verified_publications"]], target)

    def test_expected_union_cannot_omit_or_add_an_ordinal(self):
        sources = [self.project([1, 5]), self.project([31], single=True)]
        for target in ([1, 5], [1, 5, 31, 39], [1, 5, 31, 31], [True, 5, 31], [], [0, 5, 31]):
            with self.subTest(target=target), self.assertRaises(LabError):
                merge_resolution_witnesses(sources, self.trust, numbers=target)

    def test_mixed_checkpoints_are_rejected(self):
        base = read_proof(self.handover / "base-batch.json.gz")
        selected = select_resolution_witness(base, self.pins["base_checkpoint_sha256"], numbers=self.numbers,
                                            selected=[5, 31])
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            merge_resolution_witnesses([selected, self.project([1])], self.trust, numbers=[1, 5, 31])

    def test_a_redundant_invalid_source_cannot_be_ignored(self):
        valid = self.project([1, 5, 31])
        invalid = deepcopy(self.project([31], single=True))
        invalid["entry"]["decision_sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "does not match the trusted checkpoint"):
            merge_resolution_witnesses([valid, invalid], self.trust, numbers=[1, 5, 31])
        corrupt = deepcopy(self.project([5, 31]))
        corrupt["siblings"][0] = "0" * 64
        with self.assertRaisesRegex(LabError, "does not match the trusted checkpoint"):
            merge_resolution_witnesses([valid, corrupt], self.trust, numbers=[1, 5, 31])

    def test_invalid_sources_and_noncanonical_entries_are_rejected(self):
        for witnesses in ([], [None], [{}], [self.index.descriptor],
                          [{**self.project([1, 5]), "entries": None}],
                          [{**self.project([1], single=True), "entry": {"number": 1}}]):
            with self.subTest(witnesses=witnesses), self.assertRaises(LabError):
                merge_resolution_witnesses(witnesses, self.trust, numbers=[1])
        batch = self.project([5, 31])
        for entries in (batch["entries"][::-1], [batch["entries"][0]] * 2):
            with self.assertRaises(LabError):
                merge_resolution_witnesses([{**batch, "entries": entries}], self.trust, numbers=[5, 31])

    def test_merge_then_refresh_matches_refresh_then_merge(self):
        base = read_proof(self.handover / "base-batch.json.gz")
        head = read_proof(self.handover / "base-head.json.gz")
        delta = read_proof(self.handover / "delta.json.gz")
        pin, tip = self.pins["base_checkpoint_sha256"], self.pins["latest_publication_sha256"]
        partitions = [[1, 5, 31], [5, 9, 13]]
        target = [1, 5, 9, 13, 31]
        sources = [select_resolution_witness(base, pin, numbers=self.numbers, selected=part) for part in partitions]
        merged = merge_resolution_witnesses(sources, pin, numbers=target)
        first = refresh_resolution_batch(head, delta, merged, pin, tip, numbers=target)
        others = [refresh_resolution_batch(head, delta, witness, pin, tip, numbers=part)
                  for witness, part in zip(sources, partitions, strict=True)]
        self.assertEqual(first, merge_resolution_witnesses(others, self.trust, numbers=target))
        self.assertEqual(first, self.index.batch_witness(target))

    def test_mixed_authorities_remain_bound_to_the_original_publications(self):
        pins = read_json(self.mixed / "pins.json")
        source = read_proof(self.mixed / "refreshed-batch.json.gz")
        pin, initial, incoming = (pins[k] for k in ("advanced_checkpoint_sha256", "initial_authority_sha256", "incoming_authority_sha256"))
        def select(numbers, *, single=False):
            return select_resolution_witness(source, pin, numbers=pins["expected_publications"],
                                             selected=numbers, single=single)
        union = [1, 33, 1024]
        merged = merge_resolution_witnesses([select([1, 33]), select([1024], single=True)], pin, numbers=union)
        verified = verify_resolution_batch(merged, pin, numbers=union)
        self.assertEqual([entry["verified_authority_sha256"] for entry in verified["verified_publications"]], [initial, initial, incoming])
        packet = read_proof(self.archive / "incoming-resolution.json.gz")
        self.assertTrue(verify_checkpoint_batch_resolution(merged, packet, pin, numbers=union,
                                                           number=1024)["policy_resolution_verified"])
        with self.assertRaises(LabError):
            verify_checkpoint_batch_resolution(merged, packet, pin, numbers=union, number=1)

    def test_output_uses_independent_copies(self):
        source = self.project([1, 5])
        checked = merge_resolution_witnesses([source], self.trust, numbers=[1, 5])
        self.assertEqual(checked, source)
        checked["checkpoint"]["publication_count"] = 1
        checked["entries"][0]["number"] = 5
        self.assertEqual(source["checkpoint"]["publication_count"], 39)
        self.assertEqual(source["entries"][0]["number"], 1)

    def test_cli_writes_only_a_verified_expected_union(self):
        def cli(*args, status=0):
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                self.assertEqual(main(["resolution-history", *map(str, args)]), status, err.getvalue())
                return json.loads(out.getvalue()) if status == 0 else err.getvalue()

        with TemporaryDirectory() as directory:
            root = Path(directory)
            batch, single, output = (root / name for name in ("batch.json.gz", "single.json", "merged.json.gz"))
            write_proof(batch, self.project([1, 5]))
            write_proof(single, self.project([31], single=True))
            trust = ("--publication-checkpoint-trust", self.trust)
            inputs = ("checkpoint-merge-batch", batch, single, *trust, "--publication", 31, "--publication", 1)
            cli(*inputs, "--out", output, status=2)
            self.assertFalse(output.exists())
            cli(*inputs, "--publication", 5, "--out", batch, status=2)
            self.assertEqual(read_proof(batch), self.project([1, 5]))
            self.assertEqual(cli(*inputs, "--publication", 5, "--out", output)["publications"], [1, 5, 31])
            self.assertEqual(read_proof(output), self.index.batch_witness([1, 5, 31]))


if __name__ == "__main__":
    unittest.main()
