# Data and protocol

## Historical sources

Selected facts were manually transcribed from the historical 2022–2023 major agreements, Computer Science and Engineering, B.S., sending institution Glendale Community College. The files were retrieved from the public ASSIST application on 2026-11-22 (Asia/Shanghai). To locate a source via the main site, choose the sending and receiving institutions, academic year 2022–2023, and the major agreement. Direct artifact requests can require a normal session established by the public website.

| Destination | Official artifact | Source PDF SHA-256 | Included pages |
| --- | --- | --- | --- |
| UC Irvine | [26288138](https://assist.org/api/artifacts/26288138) | dc336f0a649647053473b8297b8abfb857658ca94abaefa47432ac26b49199cd | 1–2 |
| UC Merced | [26519273](https://assist.org/api/artifacts/26519273) | c05d6238d9012ae0d0281bda4643f8d122def4e503cb567c4d7a16b9d96eca32 | 1–3 |

The five Irvine rules cover programming, data structures, Calculus I and II, and a linked physics sequence. The nine Merced rules cover a historical preparation pair, programming, data structures, four mathematics rows and two physics pairs. The Merced extract models the printed CSE 020/021 ↔ CSE 022 reuse for each listed programming alternative. Discontinued CSE 020/021 is a zero-unit preparation check in the model. The date range, the grade requirement where the source does not specify it for the selected transfer bundle, the handling of retakes and the simulated Irvine revision are experiment conventions. Consult the source agreements for full programme and admission requirements. A versioned URL, page citation, role and local modeling choices are available in the packaged JSON.

## Policy JSON

Each policy declares schema 1, issuer, receiver, programme, version, valid_from, valid_until, unit, cap, group_caps, kind, provenance, rules and reuse. Institution, rule, option, group and version IDs use lowercase letters, digits, hyphens, dots or underscores. Dates use ISO YYYY-MM-DD with an exclusive upper boundary. Policy scopes are issuer × receiver × programme. An ordinary publication requires a distinct interval in its scope. A revision explicitly references an earlier policy commitment and adds a signed reason. Its interval must lie within the parent's effective interval, and that parent must still apply throughout the revision window. Version labels are unique within a scope.

- unit is the receiving institution's unit label. units, cap and group_caps use integers in hundredths of that unit. Set cap to null or group_caps to an empty object when unconstrained. A zero-unit rule can count toward matched requirements.
- A rule includes id, label, units, group, evidence and options. Each option contains id and all_of. Each all_of entry contains course and min_grade. Multiple options express an OR and the entries inside one option an AND. Codes are normalized for spacing and case.
- reuse contains explicit course and rules pairs. A source course consumes one allocation unless that specific pair of target rules allows reuse. A retake can change eligibility. It never creates a second allocation token.
- kind is historical-extract or synthetic. provenance contains title, url and note. Use a source HTTPS URL for a historical extract and null when appropriate for a synthetic scenario.

For each option, the engine uses the highest ranked attempt completed by the evaluation date, then the latest completion date and the attempt ID to break a grade tie. Pass, no pass, withdrawal and incomplete grades can be represented as P, NP, W and I. A letter requirement needs a comparable grade. The decision identifies an unranked attempt as a review condition.

## Transcript JSON

A transcript contains schema, issuer, holder and attempts. Use a pseudonymous holder ID. Each attempt has an id, course, grade and completed_on. The record command requires a signature from the configured issuer and binds the normalized transcript to that network and a random salt.

## Optimization

One binary variable represents one currently eligible option. Constraints limit each target rule to one option and prevent shared-course allocations unless a rule pair is exempted. A total credit cap and per-group caps use the receiving unit. The primary objective maximizes awarded units, then matched rule count. A lexicographic tie break in bounded chunks makes the chosen allocation reproducible. The sequential greedy alternative applies the same eligibility and resource constraints in normalized rule and option order.

## Review bundle

Registration commits an actor-signed policy descriptor. A receipt commits a salted and signed decision plus a commitment to the signed transcript. Records on the ledger contain only descriptors, hashes, signatures and block metadata. The local off-chain store keeps the full policies and receipts. Each block hashes its canonical header and links to the previous header hash. Each validator persists a vote before returning it. An interrupted proposal is retried at the same height with the same header. After coordinator commit, lagging replicas can catch up.

An offline review bundle contains the trust manifest, certified prefix, policy, signed transcript and signed receipt. Verify the manifest using a fingerprint obtained separately. Verification checks the event signatures, quorum, hash links, policy order, actor and artifact bindings, then recomputes the original allocation using the supported schema and solver version. The anchor-only export includes only the manifest, certified prefix and receipt digest. It confirms the existence of a commitment in the supplied prefix. To assess the current state separately, obtain a more recent trusted checkpoint.

## Effective dates and registration views

The assessment date is the valid-time axis. It selects the policy's effective interval and the grade evidence cutoff. The knowledge view is the committed ledger prefix. Within that prefix, the newest applicable registration in an explicitly validated revision lineage governs the date. A new rule for a narrow interval leaves its parent applicable outside that interval. Amend each active parent separately when a change spans different active versions.

New local block headers preserve proposal time and declare format 2. They carry a separate finalization certificate signed by a quorum of the block's validators. The certificate binds the network, block digest and local UTC timestamp assigned during finalization. A proposal waiting for quorum is absent from committed views. Timing is relative to the lab's local clock and recorded during the transaction that commits the block. Offset-aware time queries use the series of certified finalization times. For a legacy prefix, use an exact height until the first certified finalization. Height queries remain available when clocks are out of order.

The signed event for a new receipt includes the earlier knowledge height and its block digest. The verifier checks that its claimed policy is the one selected at the recorded assessment date in that prefix. Legacy receipts use their original signed policy and algorithm evidence. The original policy and transcript format and the allocation method version remain compatible with earlier exports.

Policy reads verify the committed registry and the selected policy's commitment. Valid local ledger signatures can be reused from a bounded in-memory cache keyed by public key, complete signed message and signature. The offline verifier performs fresh signature checks. Review bundles retain the v1 schema and solver version.

## Managed custody protocol

Manifest schema 2 identifies a newly initialized managed network. It enrolls distinct actor and validator public keys. Each enrollment verifies proof of possession, while the initial distribution of the manifest fingerprint establishes trust in the named participants. Its blocks use format 3 and certificate votes from any three of the four fixed validators. The proposal timestamp remains descriptive. Historical queries in this file-exchange mode use committed heights.

An actor or validator rotation is an event signed by the current key. The replacement key signs a distinct `key-possession` domain over the network, identity, role, old and new public keys, and reason. Previously used public keys are ineligible as replacements. The rotation block is verified against the keys in effect before the block. Subsequent blocks use the replacement key for that identity. The initial trust fingerprint stays fixed. Validator stores reserve one proposal digest at each height across restarts and rotations. The coordinator packages only public ledger headers, commitments and signatures for the voting step.

A managed receipt anchors both the policy `knowledge` view and the independent institution's `approval` view. The `approval` view must be immediately before the receipt block, so signatures under a retired key or an approval based on an outdated committed head are ineligible for a new record. The replay verifier resolves the actor and validator keys active at their respective heights. The standalone receipt, transcript and review bundle structures are retained. See [Managed custody](managed-custody.md) for the file exchange and rotation workflow.

The reference site is loopback-only. In local mode replica databases and keys share one host. In managed mode the validator stores and keys reside with their owners. The fixture tests use a single host in a controlled availability model. They do not measure wide-area consensus, operator compromise, throughput on production volumes, or learner outcomes.

## Long ledger reads and proof transport

The coordinator and local replicas maintain a derived SQLite receipt index. It selects a candidate block height, and the reader verifies the prefix through that height and matches the certified anchor to the requested commitment. A missing or stale index can use a verified scan. The coordinator builds an index for older stores when opened. A legacy local replica builds its index at the next synchronization. A historical proof is valid for the prefix through its receipt and can be exported from that prefix independently of later blocks. Status and the latest history still require verification of the current prefix.

The workbench history cursor binds the page to a verified height and block digest. It retains one browsable snapshot per workbench server. On a cache miss, the app can reverify the fixed prefix. Refresh checks current history. Identical canonical copies in local replicas reuse the already performed coordinator verification. Divergent records are independently verified to classify replica status.

Gzip is a file wrapper for the same portable proof JSON. Every independently imported proof still verifies the trust fingerprint, every block, applicable signer keys and the anchor. A full proof also recomputes the credit decision. Export size before compression and verification time grow with certified history length. See [Long history audit](long-history-audit.md).

## Checkpoint proof profile

The portable proof envelope with schema 2 contains an authenticated receipt entry and, for a full replay, the policy timeline for its issuer, receiver and programme. Its checkpoint descriptor commits the trust manifest digest, certified height, block digest, leaf count, Merkle root and profile. The profile sorts scope entries by the canonical scope digest and receipt entries by receipt digest, with scopes preceding receipts. The index is deterministic for an identical verified archive. SHA-256 leaf and node encodings use the domain-separated Merkle construction described in [RFC 9162 Section 2.1.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.1).

The receipt entry binds its original public event, block digest, height, policy knowledge view and the public keys active when it was committed. The scope entry binds all registrations in that scope through the checkpoint. Full replay selects the applicable version at the original knowledge height and checks the signed private evidence using the historical issuer and receiver keys. The number of policies in scope contributes to compact full-proof size. The compact anchor variant carries only the receipt entry witness.

The verifier independently audits the signed history with the known manifest fingerprint to establish a trusted checkpoint, or obtains that fingerprint through an independent trust channel. Every checkpoint covers a fixed historical prefix. The underlying signed archive is authoritative for the checkpoint audit. Receipt verification requires both expected fingerprints, verifies inclusion and replays the decision as applicable. The receipt proof supplies its descriptor for comparison with the expected checkpoint fingerprint. See [Checkpoint verification](checkpoint-verification.md).

## Checkpoint continuation

The offline auditor can save a verified public archive with the canonical SHA-256 of its manifest and certified block records, including each vote and finalization certificate. Keep that archive fingerprint from the prior independent audit. A continuation contains the manifest fingerprint, base height, base block digest and a nonempty ordered sequence of signed blocks. The auditor compares the stored archive to the trusted digest, reconstructs its policy registry and active and retired keys, and verifies the continuation with the same block checks as a full audit.

The resulting checkpoint derives from the combined history using the same sorted index and descriptor. The update verifies every new block and reads the existing public archive to authenticate it and rebuild the index. This keeps the original cryptographic evidence available for a fresh audit. A separately expected height or head can pin the target when the requested update has a known endpoint. The refresh workflow uses the archive fingerprint. Offline compact receipt verification uses the manifest and resulting checkpoint fingerprints.

## Batch proof profile

The schema 3 envelope carries the same manifest and checkpoint descriptor as schema 2. It supplies strictly increasing leaf indices with their entries and a shared sequence of sibling hashes. At each level, the verifier visits active indices in increasing order and consumes a sibling hash only when the sibling position exists outside the active set. It advances the computed parents and carries an unpaired node unchanged. Verification requires exact consumption of the supplied hashes and equality with the trusted root.

A full batch includes the exact policy scope leaves needed by its receipts. The policy bodies are keyed by their commitments. The signed transcripts and receipts are keyed by receipt commitment. Each receipt uses its own policy view and historical signer keys for offline replay. An anchor batch includes the receipt leaves and verifies their commitments. When the reviewer supplies the independently expected receipt set, the verifier requires an exact match. The schema 3 envelope carries no new checkpoint profile or ledger event type.

## Review plan and scoped disclosure

A review plan contains the independently audited manifest and checkpoint fingerprints and a sorted list of unique receipt commitments. Each row specifies `replay` or `anchor`. The SHA-256 of the canonical plan is agreed independently by the parties conducting the review. The plan fingerprint fixes the snapshot, selection and disclosure mode, and can be verified before private artifacts are read.

The schema 4 envelope adds the plan to the shared multiproof. Its authenticated receipt leaves match the complete plan. Its policy timeline leaves, committed policy documents and private evidence maps match the replay requirements exactly. The verifier checks the three expected fingerprints, authenticates the Merkle root and returns individual anchor or replay results after all checks succeed. The archive, checkpoint and ledger event formats retain their existing definitions. The review's operator controls the authorized recipients of any transcript evidence.

## Signed review attestations

The reviewer signs a versioned summary in the Ed25519 domain `review-attestation` only after validating a schema 4 proof against the independently agreed manifest, checkpoint and plan fingerprints. The signed fields include these fingerprints, checkpoint height, reviewer public key, local issue time, receipt counts, and SHA-256 digests of the original proof and canonical verification result. The attestation contains no transcripts or per-receipt results.

Signature verification checks an independently trusted raw reviewer public key fingerprint and the expected plan fingerprint. The signed time is the reviewer's reported UTC clock. Acceptance in this mode attests what the trusted signer reported. When the original proof is available, a recheck compares its canonical digest and re-executes verification against independent ledger and plan inputs. The verifier compares the signed scope and result commitment, and records whether this recheck was performed.

## Joint review attestations

A reviewer policy records the plan fingerprint, the sorted authorized reviewer key fingerprints and the signature threshold. Both the collector and the final verifier check its canonical JSON SHA-256 against an independent reference. The joint envelope contains this policy and the individual signed attestations ordered by reviewer key fingerprint.

Every included reviewer must be authorized, distinct and validly signed. The manifest, checkpoint, plan, proof digest, result digest and receipt counts must match across all summaries, and the number of accepted keys must meet the policy threshold. With the original proof and independent ledger fingerprints, one evidence recheck validates the common committed result. The threshold expresses an approval rule over authorized keys. Institutional enrollment and key custody establish the people or organizations that those keys represent.

## Reviewer policy revision history

The schema 1 policy-history envelope contains an initial reviewer policy and an ordered sequence of changes. Revision 1 is identified by the canonical initial policy digest. A change body contains its schema and kind, the next revision number, the preceding revision fingerprint and the successor policy. Its canonical SHA-256 identifies the new revision. All versions in one history use the same review-plan fingerprint.

Approvals sign the same body with Ed25519 in the `review-policy-change` domain. The verifier requires sorted, distinct signers authorized by the preceding or successor roster. It checks each signature and counts signers separately against the two thresholds. A key present in both rosters can satisfy one signature in each count. A policy with identical contents to an earlier revision still has a distinct revision fingerprint because the change body includes its ordinal and predecessor.

Verification starts from an independently trusted initial policy digest and finishes at the independently expected latest revision fingerprint. Obtaining the current expected endpoint is part of the institution's publication and trust process. A schema 1 joint confirmation can be assessed against any selected revision with matching policy content. The check reports `revision_binding_verified: false` to identify confirmations whose signed summaries only bind the plan and evidence.

## Revision-bound reviews

A schema 2 signed summary adds `policy_revision_sha256` to the signed body and uses the `review-attestation-revision` signature domain. Issuance authenticates the history against both independent fingerprints, checks the signer's eligibility under the verified latest revision and verifies the plan-bound evidence. The signed body continues to commit the proof and result. The issue time is reported by the signer's local clock.

A schema 2 joint confirmation collects schema 2 summaries. Verification authenticates the history to the expected endpoint, selects the specified revision or the verified latest revision, and checks that every authorized signer used that revision fingerprint. If policy content recurs, its new revision fingerprint keeps the signatures separate. The CLI can require revision-bound signatures and recheck the evidence once. The workbench accepts a history and a revision-bound confirmation together and verifies the authorization and signatures offline.

## Policy divergence evidence

Comparison verifies each policy history from the same trusted initial policy to its own independently expected endpoint. It compares the successive revision fingerprints to find the longest common prefix. The fingerprints commit the revision bodies. Valid approval collections over an identical body therefore describe the same revision. The verified prefixes determine whether one history extends the other or whether they carry distinct successors.

A schema 1 divergence exhibit contains the shared policy history once and the two signed changes immediately following it. Offline verification requires the independently trusted initial policy SHA-256. The verifier authenticates the prefix, checks both changes against its endpoint, enforces both thresholds for each change and requires distinct successor fingerprints. It reports the common predecessor, the distinct successors and the intersection of approving keys from the predecessor's roster. The exhibit represents those signed revisions. Later endpoints are checked by comparing the complete histories. Collecting both histories and resolving which revision governs operations belongs to the institution's publication and review process.

## Institutional resolution

A schema 1 resolution authority profile binds a specific initial policy fingerprint, ordered resolver key fingerprints and an approval threshold. A decision commits the authority fingerprint, the SHA-256 of the divergence exhibit, the selected immediate successor and the selected history's exact endpoint. Resolvers sign the same canonical body in the `review-policy-resolution` domain. Signing checks the exhibit, the selected history and its independently expected endpoint. The endpoint must descend from one of the exhibit's verified successors.

The packet includes the authority profile, exhibit, selected history, decision body and approvals. Recipients use independently trusted authority and expected decision fingerprints. Verification checks each distinct resolver signature, both successor authorizations and all links to the selected endpoint. The optional CLI check requires a joint review whose signers bind that exact revision. A recipient may also rerun the original proof. Institutions maintain the expected decision fingerprint when an adopted endpoint changes, and determine how authority profiles or conflicting signed decisions are handled.

## Resolution publication history

The schema 1 history header contains the authority profile and the digest of a verified divergence exhibit. Its canonical digest is the predecessor of the first publication. A publication body binds that history digest, the next consecutive number, the preceding publication fingerprint and the decision fingerprint. Each resolver signs it in the `review-policy-resolution-publication` domain. Signers and collectors verify the resolution packet against the expected decision digest and its divergence scope before approving the next entry.

Recipients supply an independently trusted authority and an independently expected latest publication fingerprint. Authentication checks every link and the authority's distinct signature threshold. A repeated decision digest can appear at several positions, each with its own publication fingerprint. The history retains signed publications and decision fingerprints. For the selected current or historical entry, provide its archived resolution packet to verify the corresponding decision. With an accompanying confirmation, the verifier also checks the reviewer's exact signed revision and can independently recheck the original evidence. Publication order is relative to the authenticated history. Institutions distribute the expected endpoint and retain separately verifiable resolution packets.

## Authority handover

A schema 2 history preserves the original schema 1 header fingerprint and can contain regular publications and handover publications. The handover body commits the successor authority profile in addition to the usual history, number, predecessor and decision fingerprints. Outgoing and incoming approval lists use separate Ed25519 signature domains. The verifier enforces each roster's threshold independently and derives the active authority from the verified sequence.

The handover publication adopts the first resolution packet issued by the successor authority. The successor retains the initial reviewer policy and divergence scope. Later regular publications use the successor roster and threshold. Historical review uses the authority effective at the selected publication and checks the packet and confirmation under that authority. The initial authority and expected latest publication remain the independent verification inputs.

## Publication checkpoint

The auditor authenticates the full sequence and both approval thresholds at every handover using independent initial-authority and endpoint fingerprints. A schema 1 publication checkpoint commits the history root, initial authority, divergence fingerprint, expected terminal publication, publication count and Merkle root. Each ordered leaf contains its one-based publication number, publication body SHA-256, decision SHA-256 and effective authority SHA-256. At a handover the effective authority is the incoming one. Leaves use the same domain-separated Merkle construction as receipt proofs, with an unpaired node carried to the next level.

The recipient obtains the checkpoint's canonical SHA-256 through an independent audit or a trusted institutional channel. The witness includes the descriptor, one indexed leaf and its exact sibling path. Verification checks the pinned descriptor, the requested ordinal and the path. With no ordinal supplied, the verifier expects the last publication in the pinned checkpoint. Verifying a resolution packet and a matching confirmation uses the authority and decision fingerprints from the authenticated leaf. Any original receipt evidence keeps its own manifest and receipt-checkpoint fingerprints.

## Publication checkpoint extension

A schema 1 delta contains the base publication count, base endpoint fingerprint, base authority profile and a nonempty sequence of signed publication records. The CLI export audits the source history and reads the authority in effect at the chosen base. To apply the delta, the recipient authenticates the retained head witness against the trusted checkpoint fingerprint and checks the base count, endpoint and authority against that witness. New records follow the original history anchor and consecutive predecessor and ordinal checks. Regular publications use the active authority. Handover records must satisfy both signed rosters before the successor becomes effective. The update is accepted at the independently expected new publication fingerprint.

The siblings in a verified rightmost Merkle path are the complete subtrees to its left. The set bits of the last leaf's zero-based index give the levels of those subtrees from right to left. The verifier adds the last leaf and the verified new leaves, using the existing hash order to join adjacent subtrees. It then derives the root and rightmost path for the new witness. The descriptor and witness use the same schema as a full audit and can serve as the next base.

## Historical witness refresh

The verifier requires an explicitly expected historical ordinal and authenticates its retained witness and the head witness under the same trusted base descriptor. It verifies the signed continuation to the expected new endpoint using the extension rules. It then walks the sibling positions for the historical leaf in the enlarged tree. A complete sibling wholly inside the base keeps its authenticated hash. A sibling that crosses the old edge is rebuilt from the complete smaller subtrees on that edge and the appended leaves in its range. A sibling wholly beyond the base is derived from its verified new leaves. The verifier checks the updated path against the independently derived extension root.

The output uses the same descriptor and witness schema as a full audit. The leaf keeps the historical publication number, decision and authority recorded when the decision was published. An earlier witness still authenticates its original pinned snapshot. To refresh that proof again, use it together with the corresponding head witness and the next signed continuation. A full audit can issue a historical witness when a retained one is unavailable.

## Batch publication witnesses

A schema 1 batch witness commits the same checkpoint descriptor and publication leaves as single witnesses. It includes the selected leaves in strictly increasing ordinal order and one list of missing sibling hashes. At each level the verifier supplies siblings only for active nodes that have a sibling outside the selected nodes. The verifier requires exact equality with the independently specified publication set and consumes each listed hash in canonical order.

To refresh, authenticate the batch and head witness under the pinned base and verify the signed continuation once. Walk the frontier for the same selection in the advanced tree. Reuse sibling hashes for complete subtrees inside the base. For frontier subtrees crossing the old edge or beyond it, use the authenticated head path and verified new leaves. The result is checked against the advanced Merkle root. A selected member can be used to verify its resolution and receipt evidence against its authenticated decision and authority.

## Deriving a subset witness

The selector takes a source batch, its independently expected ordinal set, its pinned checkpoint fingerprint and a requested subset. Source and requested ordinals must be distinct and within the checkpoint. During source multiproof verification, each level contains the source's active hashes and the corresponding supplied siblings. A required sibling for a subset is one of those hashes. The verifier collects these hashes in canonical order while reconstructing the entire source root.

After successful source verification, the selector emits the same checkpoint descriptor, the requested leaves and the collected hashes. It checks the derived witness against the same root. The standard single-witness format is available for a one-member subset. Unselected leaves are represented through hashes where the new witness requires them. The descriptor still includes the original publication count and checkpoint metadata.

## Merging witnesses for an expected union

The merger accepts single or batch publication witnesses against one independently trusted checkpoint. It verifies every input's publication leaves and hashes, then checks that the union equals the independently expected set of publication ordinals. Identical leaves at the same ordinal coalesce. The retained record continues to carry its original decision and issuing authority.

The merger indexes authenticated sibling hashes by tree level and node position. A sibling needed by the union is outside every source selection and neighbors at least one subtree selected by a source. That source supplies its hash in the required position. The merger emits these hashes in canonical order and independently verifies the resulting standard batch witness against the same root.
