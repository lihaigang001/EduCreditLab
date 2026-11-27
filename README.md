# EduCreditLab

[![DOI](https://zenodo.org/badge/github/1473015741.svg)](https://doi.org/10.5281/zenodo.24564737)

EduCreditLab computes how courses from one institution satisfy selected requirements at another institution. It explains each match, compares dated policies, and produces a review bundle that another reviewer can verify and replay. The source distribution includes an English command-line interface and a Chinese browser workbench.

## Install and run

Use Python 3.11 or later. Create a virtual environment, activate it, and install from this directory.

    python -m venv .venv
    # Windows: .venv\Scripts\activate
    # macOS/Linux: source .venv/bin/activate
    python -m pip install .

On Windows, run **Start_EduCreditLab.cmd** to create the environment and start the Chinese workbench. The launcher installs dependencies when needed and reinstalls the bundled version 1.28.1 application wheel each time it starts, so the packaged files replace any stale copy in the virtual environment. The initial install needs access to Python package wheels. The experiments and workbench subsequently run offline.

For an upgrade, stop the running workbench and retain a copy of its workspace directory. The launcher refreshes the bundled version 1.28.1 application wheel at startup and reuses the existing workspace. Opening the coordinator adds a receipt index to an older workspace. For a custom workspace, start the command below with your workspace path.

    educreditlab --workspace ./workbench serve

Open **http://127.0.0.1:8765**. A fresh workspace registers the bundled policies. Choose the programming and calculus transcript to compare Irvine and Merced. Change the comparison to policy versions, then issue a review receipt from the result card. The ledger page can replay and export the receipt.

The workbench reuses the same receipt for subsequent submissions with the same normalized transcript, policy snapshot and evaluation date. A full review bundle includes the evidence needed to recompute the decision. An anchor export supports signature and commitment checks without the transcript or decision.

History shows 40 records per page. Changing pages uses the same verified head. Refresh opens the latest committed view. Choose the gzip download for proofs that exceed the browser's 16 MiB upload limit as raw JSON. The browser accepts gzip files up to 16 MiB and checks up to 64 MiB of decoded data. The CLI accepts plain JSON and gzip proofs.

    educreditlab --workspace ./workbench bundle <receipt digest> --out ./review.json.gz
    educreditlab verify ./review.json.gz --trust <64-character fingerprint>

For a long ledger and repeated reviews, audit one signed archive to establish a checkpoint. Compact proofs bind the receipt, then-active actor keys and scoped policy timeline to that checkpoint. A compact full proof retains the private artifacts needed to recompute the decision. The verifier supplies an independently trusted checkpoint fingerprint in addition to the manifest fingerprint. See [Checkpoint verification](docs/checkpoint-verification.md) for the trust procedure and the 10,000-block demo.

When the ledger grows, export its signed continuation with `checkpoint export --from-height` and audit it with `checkpoint extend`. Keep the public archive and its canonical SHA-256 from the prior independent audit. The extension authenticates that archive, restores the policy and key history, checks each new block and derives the updated checkpoint. Use `--expect-height` or `--expect-head` when the intended endpoint is known.

Use `bundle-batch` to export multiple receipts from one checkpoint. A batch shares the checkpoint, Merkle proof and policy documents. The full variant replays each decision. The anchor variant checks the commitments without sharing transcripts. Provide each independently expected receipt digest with `verify --expect-receipt` when the review requires an exact set. See [Batch review](docs/checkpoint-verification.md#批量核验回执) for commands and bundled samples.

Use `review-plan` when a single batch requires different disclosure modes for different receipts. The plan fixes the manifest, checkpoint and treatment of every receipt. Share the agreed plan fingerprint independently. The issuer uses `bundle-review` to load grades only for replay items, and the reviewer verifies the resulting batch with `--plan-trust`. The workbench shows both replay and anchor results. See [Review plans](docs/checkpoint-verification.md#按审核计划披露证据).

Use `review-attest` to verify the original plan-bound proof and sign a summary containing the plan, proof and result digests and aggregate counts. An oversight reviewer can authenticate the summary using an independently trusted reviewer public key fingerprint and the expected plan fingerprint. An authorized recipient with the original proof can replay it and compare the committed result using `verify-attestation --proof`. See [Review attestations](docs/checkpoint-verification.md#签发和核验审核确认书).

Use `review-quorum` to specify the authorized reviewer keys and signature threshold for a plan. After the reviewers produce their signed summaries, `bundle-quorum` checks each signature and joins the statements for an identical proof and result. Recipients verify the joint record using the independently trusted reviewer policy fingerprint. With the original proof, `verify-quorum --proof` rechecks the shared evidence once. See [Joint review attestations](docs/checkpoint-verification.md#多方审核确认书).

Use `policy-history` when the reviewer roster or threshold changes within an agreed plan. Each proposed successor requires the signature thresholds of both reviewer policies. Verify the history against the independently confirmed initial policy and expected latest revision fingerprints. The workbench verifies rule histories. The CLI also checks a joint review against the verified latest rule or a historical revision you select. See [Reviewer policy history](docs/checkpoint-verification.md#审核规则历史).

Issue reviews with `policy-history attest` to sign the exact rule revision along with the proof and result. Use `policy-history bundle` to collect matching signatures and `policy-history review --require-revision-binding` to verify them. The workbench can verify the bound joint record together with its rule history. Legacy records remain readable and report whether the signatures bind a revision. See [Revision-bound reviews](docs/checkpoint-verification.md#绑定规则版本的审核确认书).

Use `policy-history compare` when two institutions have supplied independently pinned versions of one rule history. It checks both histories and distinguishes matching revisions, an ordinary extension and a divergence. Export an exhibit of the shared prefix and its two signed successors, then verify it with `policy-history verify-divergence` or the workbench. See [Policy divergence evidence](docs/checkpoint-verification.md#审核规则分歧证据).

After an institution decides which revision to use, a separately trusted authority roster can sign that exact choice with `policy-history resolution-sign`. Verify the assembled packet against independent authority and decision fingerprints with `verify-resolution`. Adding `--review` checks a joint confirmation at the selected revision. The workbench verifies the resolution packet. See [Institutional resolution](docs/checkpoint-verification.md#审核规则分歧裁定书).

Use `resolution-history` to authorize and verify successive publications of the institution's decisions for one divergence. The verifier checks the signed sequence against an independently expected endpoint. The CLI can check a stored resolution and its confirmation for the latest entry or a specifically selected earlier entry. The workbench verifies the publication history and displays the current decision fingerprint. See [Publication history](docs/checkpoint-verification.md#院校裁定发布历史).

An institution can use `resolution-history handover-sign` and `handover-append` when its resolution authority changes. The outgoing and incoming rosters each approve the same record, which installs the successor and publishes its first decision. Historical reviews use the authority effective at the selected publication. See [Authority handover](docs/checkpoint-verification.md#院校裁定权限交接).

Use `resolution-history checkpoint` to audit a signed publication history to an independently expected head and export a witness for one publication. `resolution-history checkpoint-verify` authenticates the publication number, decision and authority against an independently obtained publication checkpoint fingerprint. It can additionally verify the corresponding resolution, joint confirmation and original evidence. Select `--publication N` explicitly for an earlier publication. The workbench supports verification of the inclusion witness. See [Publication checkpoints](docs/checkpoint-verification.md#裁定发布检查点).

Keep the checkpoint fingerprint and the head witness if you plan to verify later publications. The publisher can export a signed suffix with `resolution-history checkpoint-delta`. The recipient uses `resolution-history checkpoint-extend` with the saved witness, signed suffix, trusted checkpoint fingerprint and independently expected new publication fingerprint. The update verifies each new publication, including both thresholds of a handover, and returns the new head witness. See [Extending a publication checkpoint](docs/checkpoint-verification.md#接续裁定发布检查点).

If you also retained a witness for a historical publication at the base, run `resolution-history checkpoint-refresh --publication N` with both retained witnesses and the same signed suffix. The output proves publication `N` under the new checkpoint using the decision and authority recorded in its original leaf. Verify it with the new checkpoint fingerprint and the same explicit ordinal. See [Refreshing a historical witness](docs/checkpoint-verification.md#更新历史裁定证明).

For an exact set of publications, use `checkpoint-batch` to export a shared witness and `checkpoint-refresh-batch` to advance it with the base head witness and a signed continuation. Repeat `--publication` for every intended ordinal. `checkpoint-verify-batch` and the workbench require the independently expected set and checkpoint fingerprint. To verify the decision and receipt evidence for one member, supply `--select-publication N`, its resolution and the applicable review inputs. See [Batch publication proof](docs/checkpoint-verification.md#批量裁定发布证明).

Use `checkpoint-select-batch` to derive a witness for a subset of a retained batch at the same checkpoint. Repeat `--publication` for the independently expected source set and `--select-publication` for the ordinals to retain. Use `--single` with exactly one selection to export a standard single witness. See [Selecting publications from a batch](docs/checkpoint-verification.md#从批量证明提取指定发布).

Use `checkpoint-merge-batch` to combine single and batch publication witnesses at one trusted checkpoint. Supply the input files and repeat `--publication` for the exact expected union. The resulting standard batch witness includes one entry per verified publication and can be checked by `checkpoint-verify-batch` or the workbench. See [Merging publication witnesses](docs/checkpoint-verification.md#在同一检查点合并裁定证明).

Use `checkpoint-advance-merge-batch` when participants hold proofs pinned to the base, the advanced checkpoint, or both. Supply the retained base head witness and its trusted fingerprint, the signed continuation, the independently expected new publication fingerprint, the witness files and the exact expected union. The command verifies the continuation once, advances the combined base proofs and exports a standard batch at the derived checkpoint. See [Merging across a checkpoint extension](docs/checkpoint-verification.md#合并检查点更新前后的裁定证明).

To derive proofs for entries already in the signed continuation, repeat `--include-new-publication N` on the same command. Supply the independent final list with repeated `--publication N`. The base head and continuation suffice for an additions-only batch. For a batch spanning both checkpoints, also supply retained witnesses for the earlier publications. See [Proving newly appended publications](docs/checkpoint-verification.md#从签名增量导出新增裁定证明).

Use `checkpoint-chain-merge-batch` when signed continuations are held as a sequence. Supply the base head witness and independently trusted checkpoint fingerprint. Repeat `--step DELTA EXPECTED_SHA256` in chronological order with each continuation and its independently expected head publication fingerprint. The command accepts proofs at the base and any proven step endpoint, refreshes each earlier group directly to the final checkpoint and exports a standard batch for the exact expected set. See [Merging across consecutive signed continuations](docs/checkpoint-verification.md#合并多段增量中的裁定证明).

When several groups need the same changed sibling at the final checkpoint, v1.26.0 computes its Merkle subtree root once per merge. Each source witness and the resulting batch are still verified against their respective roots.

Version 1.27.0 also reuses the Merkle leaf hashes produced during each verified append. The current operation uses them to refresh earlier proofs and derive selected new publications. Verification reconstructs leaf hashes directly from each external proof's entries.

In v1.28.0 the chain-merge command decodes each continuation as its stage is verified. The command retains compact publication entries and leaf hashes for final proof construction. It exports the batch after all stages and source proofs pass verification.

## Trace a same-year policy amendment

In the workbench, choose the same-date policy view, register the optional synthetic amendment, and calculate the comparison. The same synthetic transcript has 16 quarter units in the earlier view and 4 quarter units in the later view for 2023-06-15. The effective interval of that amendment is 2023-06-01 through 2023-06-30. The amendment is registered through the specific demo action.

    educreditlab --workspace ./revision-study demo-revision --out ./revision-output
    educreditlab --workspace ./revision-study timeline

The demo writes a comparison, independently checkable receipts for both views, and the manifest fingerprint. Inspect their accepted policy version, effective date and knowledge block. Use a fresh directory for a clean run. Run the general benchmark for the temporal grid and the earlier allocation and ledger checks.

For custom revisions, register the revised policy JSON with the digest of its active parent from the timeline. The covered interval must lie within the parent's scope and dates. Use the parent that remains active throughout the intended interval.

    educreditlab --workspace ./custom revise ./amended-policy.json --supersedes <parent SHA-256> --reason "Published threshold correction"
    educreditlab --workspace ./custom preview ./transcript.json --receiver receiving-university --programme cse-bs --as-of 2023-06-15 --known-height 1
    educreditlab --workspace ./custom compare-policy ./transcript.json --receiver receiving-university --programme cse-bs --as-of 2023-06-15 --before-height 1 --after-height 4

Replace the example heights with those from your timeline. The preview and record commands accept either a committed height or a certified ISO 8601 time through `--known-at`. The time requires a UTC offset. Height remains the exact ordering reference, including for workspaces upgraded from versions with only proposal times.

## Independently managed keys and planned rotation

The managed consortium starts from a public trust manifest. Institution owners sign policies, transcripts and receipt approvals on their own device. Four independent validators retain durable vote state, and the coordinator can commit with any three distinct valid votes. The coordinator stores no private signing keys. Key owners keep passphrase-encrypted Ed25519 PKCS#8 files. Planned rotation is signed by the current key and includes a proof of possession from the replacement key. A certified rotation at height H changes the active key from H+1. Offline verification uses the keys active at each proof block, so earlier receipts survive both institution and validator rotation. The same initial manifest fingerprint anchors both proofs.

    educreditlab custody demo --out ./custody-output

The demo exports two signed review bundles, a summary and the fingerprint for the synthetic network. The full workflow is in [Managed custody](docs/managed-custody.md). The workbench shows public key changes and replays exported receipts. Signing in managed mode uses the command-line workflows on each key owner's device. Managed history uses heights. New managed networks are initialized separately, and local workspaces retain their original mode when upgraded.

## Reproduce the bundled experiments

    educreditlab --workspace ./case-study demo --out ./demo-output
    educreditlab benchmark --out ./replication --repeats 30
    python -m unittest discover -s tests -v

The demo prints the trust-manifest fingerprint and writes it in demo-output/trusted-manifest-sha256.txt. Obtain the expected value from the issuing research workspace through an independent channel before verifying an exported bundle.

    educreditlab verify demo-output/review-bundle.json --trust <64-character fingerprint>

The release includes CSV and JSON measurements from several software versions in **results/**. The allocation benchmark produces 1,024 decisions over 512 synthetic transcripts and two historical policy extracts. The temporal experiment adds 600 decisions over 75 synthetic transcripts, four assessment dates and two views of the ledger. A separate set of 64 synthetic allocation cases uses exhaustive enumeration as the objective reference and compares a sequential greedy allocator. The replay experiment measures 30 recorded receipts per local backend after one warm-up receipt. Timing is specific to the host, filesystem and ledger history length. The managed custody demonstration uses the separate `custody demo` command.

The v1.3.0 and v1.4.0 long-history results are documented in [Long history audit](docs/long-history-audit.md). The v1.5.0 checkpoint audit compares both proof formats and measures the initial audit separately. The v1.6.0 extension experiment compares a full public archive audit with incremental updates to the same 10,000-block head. See [Checkpoint verification](docs/checkpoint-verification.md) for the commands and trial definitions.

The v1.7.0 batch experiment uses the same 10,000-block certified history and selected groups of 8, 32 and 128 synthetic receipts. It measures a shared batch proof, individual compact proofs and common gzip compression of the individual proof documents. Raw trials and portable proof samples are in `results/batch-proof/`.

The v1.8.0 review plan experiment assigns 0, 16, 64 or 128 of the same 128 receipts to full replay. It compares a plan-bound package with equivalent separate batches for replay and anchor items. Raw trials and CLI and browser samples are in `results/review-plan/`.

The signed review summaries for three and 128 synthetic receipts are in `results/review-attestation/`. Each has measurements for examining the signature and for rechecking the original proof with independent trust inputs.

The v1.10.0 joint review cases use two of three reviewer keys and three of four reviewer keys. The fixtures, policy fingerprints and measurements are in `results/review-quorum/`.

The v1.11.0 succession experiment replaces one of four reviewer keys, then changes the threshold from three to two. Signed histories, matching historical and current confirmations, trust inputs and raw trials are in `results/review-policy-history/`. The trials use the same original plan-bound proofs as the v1.10.0 experiment.

The v1.12.0 experiment restores the original reviewer roster and threshold at revision 3. It verifies confirmations signed at revisions 1 and 3 against their own revisions, using the same reviewers and evidence. The signed histories, confirmations, fingerprints and comparative timings are in `results/revision-bound-review/`.

The v1.13.0 experiment compares the same first rule divergence with short and extended branch histories under a fixed 128-receipt review plan. Signed histories, evidence and timings are in `results/policy-divergence/`.

The v1.14.0 experiment authorizes a specified endpoint of the same divergence using two of three resolution keys. The signed resolution packets and verification trials are in `results/policy-resolution/`. The longer case also rechecks the selected joint confirmation against its original evidence.

The v1.15.0 experiment publishes two different decisions and reinstates the first. The same two decision packets are checked using histories of 3 and 27 publication entries. The histories, signed packets, fingerprints and raw measurements are in `results/resolution-history/`.

The v1.16.0 experiment changes from an authority requiring two of three signatures to a separate authority requiring three of three. Samples and verification timings are in `results/resolution-handover/`.

The v1.17.0 experiment uses the same 3- and 27-publication histories. It measures checkpoint construction, witness verification and combined review with the matching resolution and joint confirmation. The longer case is suitable for comparing review with the full history and with one witness. Portable samples and raw trials are in `results/resolution-checkpoint/`.

The v1.18.0 experiment extends trusted bases of 31 and 1,023 publications by eight signed records each. Both updates begin with an authority handover. The derived checkpoint fingerprints and head witnesses match their respective full audits. The histories, deltas, witnesses and raw trials are in `results/resolution-checkpoint-extension/`.

The v1.19.0 experiment uses those same histories to refresh the witness for publication 1. For each endpoint, the refreshed witness matches the one generated by a complete audit, and the historical and current confirmations can be checked under the same new checkpoint. The two witnesses and raw trials are in `results/resolution-witness-refresh/`.

The v1.20.0 experiment uses the same signed histories, selects 8 or 32 publications and compares separate witness refreshes with a shared refresh and a complete audit. The larger selection includes publications authored under both authorities. Samples and trial measurements are in `results/resolution-batch/`.

The v1.21.0 experiment derives subsets of 2 and 4 publications from the earlier batches of 8 and 32. It also derives a single witness for each case. The outputs match those from a full audit at the same checkpoint. See `results/resolution-selection/` for proof files, expected ordinals and raw timings.

The v1.22.0 experiment combines four partly overlapping proofs into batches of 8 and 32 publications. Merged outputs match the proofs derived from a full audit. See `results/resolution-merge/` for source witnesses, ordinals and raw timings.

The v1.23.0 experiment combines six proof files from both sides of a signed authority handover. It compares a full audit, separate refreshes of the four base proofs, an explicit merge–refresh–merge sequence, and the combined command. The four paths produce the same batch. The result files, independently specified ordinals and raw timings are in `results/resolution-advance-merge/`.

The v1.24.0 experiment derives three publication proofs from signed continuations for histories ending at 39 and 1,031 publications. It checks both an additions-only batch and a batch combined with four retained base witnesses. A full audit provides the reference outputs. See `results/resolution-suffix-proof/` for ordinals, outputs and raw trials.

The v1.25.0 experiment chains two separately pinned continuations, combines witnesses from three checkpoints and derives one selected publication from each continuation. The final proofs match sequential one-step operations and full audits. See `results/resolution-checkpoint-chain/` for the signed continuation files, retained witnesses and raw trials.

The v1.26.0 comparison uses the installed v1.25.0 and v1.26.0 wheels on the same signed histories with four or sixteen continuation steps. Both versions produce byte-identical batches and match a full audit. The signed inputs, timed observations and leaf hash counts are in `results/resolution-refresh-reuse/`.

The v1.27.0 comparison reuses these two fixtures and alternates the order of the v1.26.0 and v1.27.0 wheels in four blocks. The per-block observations and leaf hash counts are in `results/resolution-append-hashes/`. Both wheels are checked against a fresh full audit.

The v1.28.0 comparison measures peak process memory and elapsed time for four and sixteen continuations over the same 16,415-publication synthetic history. The signed history and raw observations accompany the current wheel in `results/resolution-chain-memory/`. The [reproduction commands](docs/checkpoint-verification.md#复验原始测量) use the separately installed v1.27.0 wheel as the baseline.

## Use another institution or policy

Initialize a workspace with institution IDs, publish a policy using the example JSON shape, and choose a date within its half-open validity interval.

    educreditlab --workspace ./custom init --actors sending-college receiving-university
    educreditlab --workspace ./custom publish ./policy.json
    educreditlab --workspace ./custom preview ./transcript.json --receiver receiving-university --programme cse-bs --as-of 2023-06-15
    educreditlab --workspace ./custom sign ./transcript.json --out ./signed-transcript.json
    educreditlab --workspace ./custom record ./signed-transcript.json --receiver receiving-university --programme cse-bs --as-of 2023-06-15
    educreditlab --workspace ./custom bundle <receipt digest> --replica peer-b --out ./review.json
    educreditlab --workspace ./custom bundle <receipt digest> --anchor-only --out ./anchor.json

Policy and transcript formats are documented in [Data and protocol](docs/data-and-protocol.md). A saved CLI nonce pins the first registration view of a default-view request. Reuse the nonce to retry that request. Use a fresh nonce for a new decision under a newer view. After quorum recovery, use the sync command to finish a durable pending proposal and catch up replicas.

Use the status command to inspect the committed height, pending height and validation state of each replica. Preserve the complete workspace when restoring a coordinator. A replica has a certified history and may lack the original transcript and other off-chain artifacts needed for a full replay.

For an unregistered research comparison, the solver also accepts a policy and transcript directly.

    educreditlab solve ./policy.json ./transcript.json --as-of 2023-06-15 --method optimal

## Scope

The Irvine and Merced examples encode selected rows of ASSIST's 2022–2023 Computer Science and Engineering articulation agreements with Glendale Community College. Each derived rule cites its source page. The fixture encodes dates and any additional modeling choices explicitly. The grade records, signing identities and subsequent simulated Irvine revision are synthetic. Results concern the included rule bundles and use receiving institutions' native credit units. Formal transfer decisions belong to the receiving institution.

The local research ledger runs on one host with a single coordinator, fixed membership, simulated institutional keys and SQLite validator replicas. The local consortium mode requires three of four Ed25519 votes. The central mode requires one vote and shares the same application and solver. The managed consortium exchanges files with four fixed validators and uses one coordinator. The offline verifier checks the supplied history up to the receipt against an independently trusted fingerprint. Full review bundles contain the transcript and are for authorized reviewers. Keep demonstration workspaces local and use synthetic or appropriately authorized records. The managed implementation covers planned rotation and consensus by a fixed signature quorum. Production deployments require additional operational recovery and institutional data controls.

Source code is distributed under the MIT License. Source agreements are identified in [Data and protocol](docs/data-and-protocol.md).

## Authors

- **Haonan Zhang** — College of Teacher Education, Qiqihar University, Qiqihar, China 161003 — 2025933211@qqhru.edu.cn
- **Haigang Li** (maintainer) — College of Teacher Education, Qiqihar University, Qiqihar, China 161003 — lihaigang02292@qqhru.edu.cn

## Cite this software

The Zenodo concept DOI for this software is [10.5281/zenodo.24564737](https://doi.org/10.5281/zenodo.24564737). For the **v1.28.1** release, use its version-specific DOI: [10.5281/zenodo.24564738](https://doi.org/10.5281/zenodo.24564738).

> Zhang, H., & Li, H. (2026). *EduCreditLab* (v1.28.1) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.24564738
