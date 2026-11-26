from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import unittest

from educreditlab import cli, merkle, resolution_checkpoint
from educreditlab.cli import main
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (
    advance_and_merge_resolution_witnesses, advance_chain_and_merge_resolution_witnesses,
    audit_resolution_checkpoint, resolution_checkpoint_delta, verify_resolution_batch,
)
from educreditlab.transport import gzip_proof, read_proof, write_proof


class ResolutionCheckpointChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = Path(__file__).resolve().parents[1] / "results/resolution-checkpoint-extension/short"
        cls.pins = read_json(fixture / "pins.json")
        cls.head = read_proof(fixture / "base-witness.json.gz")
        cls.history = read_proof(fixture / "history.json.gz")
        cls.authority = cls.pins["initial_authority_sha256"]
        cls.base_pin = cls.pins["base_checkpoint_sha256"]
        cls.final_tip = cls.pins["latest_publication_sha256"]
        middle = {**cls.history, "publications": cls.history["publications"][:34]}
        middle_tip = digest(middle["publications"][-1]["body"])
        cls.tips = [middle_tip, cls.final_tip]
        cls.deltas = [resolution_checkpoint_delta(middle, cls.authority, middle_tip, from_number=31),
                      resolution_checkpoint_delta(cls.history, cls.authority, cls.final_tip, from_number=34)]
        cls.middle = audit_resolution_checkpoint(middle, cls.authority, middle_tip)
        cls.final = audit_resolution_checkpoint(cls.history, cls.authority, cls.final_tip)
        cls.sources = [cls.head, cls.middle.batch_witness([5, 31, 33]), cls.final.witness(39)]
        cls.new = [32, 38]
        cls.numbers = [5, 31, 32, 33, 38, 39]

    def merge(self, *, deltas=None, sources=None, tips=None, numbers=None, new=None):
        return advance_chain_and_merge_resolution_witnesses(
            self.head, self.deltas if deltas is None else deltas, self.sources if sources is None else sources,
            self.base_pin, self.tips if tips is None else tips, numbers=self.numbers if numbers is None else numbers,
            new_publications=self.new if new is None else new)

    def test_witnesses_from_three_checkpoints_and_signed_additions_match_full_audit(self):
        snapshot = deepcopy((self.deltas, self.sources))
        batch = self.merge(sources=self.sources[::-1], numbers=self.numbers[::-1], new=self.new[::-1])
        self.assertEqual(batch, self.final.batch_witness(self.numbers))
        self.assertEqual((self.deltas, self.sources), snapshot)
        checked = verify_resolution_batch(batch, self.final.fingerprint, numbers=self.numbers)
        authorities = [row["verified_authority_sha256"] for row in checked["verified_publications"]]
        self.assertEqual(authorities, [self.authority] * 2 + [self.pins["incoming_authority_sha256"]] * 4)

    def test_validates_each_delta_once_and_refreshes_each_earlier_group_once(self):
        with patch.object(resolution_checkpoint, "_verify_publications",
                          wraps=resolution_checkpoint._verify_publications) as verify, patch.object(
                              resolution_checkpoint, "_refresh_verified_batch",
                              wraps=resolution_checkpoint._refresh_verified_batch) as refresh:
            self.merge()
        self.assertEqual([len(call.args[0]) for call in verify.call_args_list], [3, 5])
        self.assertEqual([len(call.args[3]) for call in refresh.call_args_list], [8, 5])

    def test_each_merge_has_its_own_cache_shared_by_its_refresh_groups(self):
        with patch.object(resolution_checkpoint, "_refresh_verified_batch",
                          wraps=resolution_checkpoint._refresh_verified_batch) as refresh:
            self.assertEqual(self.merge(), self.merge(sources=self.sources[::-1]))
        first, second, third, fourth = [call.kwargs["final_subtrees"] for call in refresh.call_args_list]
        self.assertIs(first, second)
        self.assertIs(third, fourth)
        self.assertIsNot(first, third)
        self.assertTrue(first and third)

    def test_refresh_and_projection_reuse_append_hashes_but_still_hash_proof_entries(self):
        refreshed_leaf_counts = []
        projected_leaf_counts = []
        refresh = resolution_checkpoint._refresh_verified_batch
        project = resolution_checkpoint._appended_publication_batch

        def check_refresh(*args, **kwargs):
            before = leaf.call_count
            result = refresh(*args, **kwargs)
            refreshed_leaf_counts.append(leaf.call_count - before)
            return result

        def check_project(*args, **kwargs):
            before = leaf.call_count
            result = project(*args, **kwargs)
            projected_leaf_counts.append(leaf.call_count - before)
            return result

        with patch.object(merkle, "_leaf", wraps=merkle._leaf) as leaf, patch.object(
                resolution_checkpoint, "_refresh_verified_batch", check_refresh), patch.object(
                resolution_checkpoint, "_appended_publication_batch", check_project):
            proof = self.merge(sources=self.sources[::-1])
        self.assertEqual(proof, self.final.batch_witness(self.numbers))
        # Refresh hashes each source head and each retained leaf for verification.
        self.assertEqual(refreshed_leaf_counts, [4, 2])
        self.assertEqual(projected_leaf_counts, [1])

    def test_projected_append_hashes_are_still_checked_against_the_final_root(self):
        extend = resolution_checkpoint._verified_extension

        def corrupt_retained_hash(*args, **kwargs):
            result = extend(*args, **kwargs)
            kwargs["recorded_hashes"][-1] = b"\x00" * 32
            return result

        with patch.object(resolution_checkpoint, "_verified_extension", corrupt_retained_hash), self.assertRaisesRegex(
                LabError, "Merkle multiproof does not match"):
            self.merge(sources=[], numbers=self.new)

    def test_additions_only_across_three_stages(self):
        stages = []
        tips = []
        for base, size in ((31, 33), (33, 36), (36, 39)):
            history = {**self.history, "publications": self.history["publications"][:size]}
            tip = digest(history["publications"][-1]["body"])
            stages.append(resolution_checkpoint_delta(history, self.authority, tip, from_number=base))
            tips.append(tip)
        numbers = [32, 35, 38]
        self.assertEqual(self.merge(deltas=stages, tips=tips, sources=[], numbers=numbers, new=numbers),
                         self.final.batch_witness(numbers))

    def test_one_stage_keeps_the_existing_batch_format_and_exact_set(self):
        numbers = [31, 32, 33]
        sources = [self.head, self.middle.witness(33)]
        new = [32]
        expected = advance_and_merge_resolution_witnesses(
            self.head, self.deltas[0], sources, self.base_pin, self.tips[0], numbers=numbers, new_publications=new)
        self.assertEqual(self.merge(deltas=self.deltas[:1], tips=self.tips[:1], sources=sources, numbers=numbers, new=new),
                         expected)
        with self.assertRaisesRegex(LabError, "at least one publication witness"):
            advance_chain_and_merge_resolution_witnesses(self.head, self.deltas, [], self.base_pin, self.tips,
                                                         numbers=numbers)

    def test_steps_must_be_nonempty_ordered_contiguous_and_independently_pinned(self):
        for deltas, tips, message in (
                ([], [], "signed publication continuations"),
                (self.deltas, self.tips[:1], "independently expected stage publication fingerprints"),
                (self.deltas[::-1], self.tips[::-1], "delta base publication count"),
                (self.deltas[1:], self.tips[1:], "delta base publication count"),
                ([self.deltas[0], self.deltas[0]], self.tips, "delta base publication count"),
                (self.deltas, [self.final_tip, self.final_tip], "independently expected latest publication"),
                (self.deltas, [self.tips[0], self.tips[0]], "independently expected latest publication")):
            with self.subTest(deltas=len(deltas), tips=tips), self.assertRaisesRegex(LabError, message):
                self.merge(deltas=deltas, tips=tips)

    def test_successor_authority_carries_across_stages(self):
        wrong_profile = {**self.deltas[1], "base_authority": self.deltas[0]["base_authority"]}
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            self.merge(deltas=[self.deltas[0], wrong_profile])
        shortfall = deepcopy(self.deltas[0])
        shortfall["publications"][0]["approvals"]["incoming"].pop()
        with self.assertRaisesRegex(LabError, "Incoming authority approval failed"):
            self.merge(deltas=[shortfall, self.deltas[1]])

    def test_a_valid_proof_at_an_unlisted_checkpoint_is_rejected(self):
        prefix = {**self.history, "publications": self.history["publications"][:36]}
        index = audit_resolution_checkpoint(prefix, self.authority, digest(prefix["publications"][-1]["body"]))
        with self.assertRaisesRegex(LabError, "checkpoint in the verified continuation chain"):
            self.merge(sources=[*self.sources, index.witness(5)])

    def test_redundant_proof_still_requires_the_correct_stage_fingerprint_and_merkle_path(self):
        bad_checkpoint = deepcopy(self.sources[1])
        bad_checkpoint["checkpoint"]["merkle_root"] = "0" * 64
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            self.merge(sources=[*self.sources, bad_checkpoint])
        bad_proof = deepcopy(self.sources[1])
        bad_proof["siblings"][0] = "0" * 64
        with self.assertRaisesRegex(LabError, "Merkle"):
            self.merge(sources=[*self.sources, bad_proof])

    def test_no_implicit_new_entries_and_no_missing_stage_source(self):
        for sources, numbers, new in ((self.sources[::2], self.numbers, self.new),
                                      (self.sources, self.numbers[:-1], self.new),
                                      (self.sources, self.numbers, self.new[:1])):
            with self.subTest(sources=len(sources), numbers=numbers, new=new), self.assertRaisesRegex(
                    LabError, "exactly the expected publication numbers"):
                self.merge(sources=sources, numbers=numbers, new=new)
        with self.assertRaisesRegex(LabError, "after the base checkpoint"):
            self.merge(new=[31, 38])

    def test_cli_writes_a_canonical_batch_and_preserves_input_delta(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            paths = [folder / f"artifact-{index}.json.gz" for index in range(6)]
            for path, document in zip(paths, [self.head, *self.deltas, *self.sources], strict=True):
                write_proof(path, document)
            head, first, second, *sources = paths
            output = folder / "merged.json.gz"
            arguments = ["resolution-history", "checkpoint-chain-merge-batch", str(head), *map(str, sources),
                         "--publication-checkpoint-trust", self.base_pin, "--step", str(first), self.tips[0],
                         "--step", str(second), self.tips[1]]
            numbers = [part for n in self.numbers for part in ("--publication", str(n))]
            selected = [part for n in self.new for part in ("--include-new-publication", str(n))]
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                before = second.read_bytes()
                self.assertEqual(main([*arguments, *numbers, *selected, "--out", str(second)]), 2)
                self.assertIn("separate from the input", stderr.getvalue())
                self.assertEqual(second.read_bytes(), before)
                self.assertEqual(main([*arguments, *numbers[2:], *selected, "--out", str(output)]), 2)
                self.assertFalse(output.exists())
                self.assertEqual(main([*arguments, *numbers, *selected, "--out", str(output)]), 0, stderr.getvalue())
            self.assertEqual(json.loads(stdout.getvalue())["publications"], self.numbers)
            self.assertEqual(output.read_bytes(), gzip_proof(self.final.batch_witness(self.numbers)))

    def test_cli_reads_and_verifies_each_stage_before_loading_the_next(self):
        with TemporaryDirectory() as temp:
            folder = Path(temp)
            head = folder / "head.json.gz"
            steps = [folder / "first.json.gz", folder / "second.json"]
            output = folder / "merged.json.gz"
            write_proof(head, self.head)
            for path, delta in zip(steps, self.deltas, strict=True):
                write_proof(path, delta)
            arguments = ["resolution-history", "checkpoint-chain-merge-batch", str(head),
                         "--publication-checkpoint-trust", self.base_pin]
            for path, tip in zip(steps, self.tips, strict=True):
                arguments.extend(("--step", str(path), tip))
            for number in self.new:
                arguments.extend(("--publication", str(number), "--include-new-publication", str(number)))
            arguments.extend(("--out", str(output)))
            events = []
            verify = resolution_checkpoint._verify_publications

            def load(path):
                if Path(path) in steps:
                    events.append(("read", Path(path)))
                return read_proof(path)

            def verify_stage(records, *args, **kwargs):
                result = verify(records, *args, **kwargs)
                events.append(("verified", len(records)))
                return result

            with patch.object(cli, "read_proof", side_effect=load), patch.object(
                    resolution_checkpoint, "_verify_publications", side_effect=verify_stage), redirect_stdout(
                        StringIO()), redirect_stderr(StringIO()) as stderr:
                self.assertEqual(main(arguments), 0, stderr.getvalue())
                expected = [("read", steps[0]), ("verified", 3), ("read", steps[1]), ("verified", 5)]
                self.assertEqual(events, expected)
                prior = output.read_bytes()
                self.assertEqual(prior, gzip_proof(self.final.batch_witness(self.new)))
                events.clear()
                steps[1].write_text("{", encoding="utf-8")
                self.assertEqual(main(arguments), 2)
                self.assertIn("Invalid JSON", stderr.getvalue())
                self.assertEqual(events, expected[:-1])
                self.assertEqual(output.read_bytes(), prior)


if __name__ == "__main__":
    unittest.main()
