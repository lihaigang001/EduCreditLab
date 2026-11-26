# 检查点核验

精简证明适用于同一已审核账本快照上的重复复核。检查点由已核验的完整历史确定，包含初始信任清单摘要、区块高度、链头摘要和 Merkle 根。核验方先通过可信清单指纹逐块检查一次档案，之后可用同一个检查点指纹验证该检查点中的多张回执。核验方可自行建立检查点，也可通过独立可信渠道取得指纹。

## 从已提交账本导出

使用固定区块高度导出签名档案，再以同一高度导出一张回执的精简完整证明。`H` 为实际已提交高度，`RECEIPT` 为回执摘要。档案只有公开账本信息。默认的精简完整证明还包含成绩单和回执证据，应按原有成绩数据授权分享。加上 `--anchor-only` 可生成不含课程成绩的精简存证证明。

```bash
educreditlab --workspace ./workbench checkpoint export --height H --out ./archive.json.gz
educreditlab --workspace ./workbench bundle RECEIPT --compact --checkpoint-height H --out ./review.json.gz
```

## 建立独立可信的指纹

`MANIFEST_SHA` 为核验方已通过独立渠道确认的初始清单指纹。审计命令验证源档案中的区块和历次换钥，重新推导检查点指纹。也可使用原有的完整前缀证明作为源档案。请核对预期区块高度和链头摘要。仅从来件精简证明复制的检查点摘要无法建立独立信任。

```bash
educreditlab checkpoint audit ./archive.json.gz --trust MANIFEST_SHA --out ./trusted-checkpoint.json
```

## 在固定检查点内核验回执

用上一阶段独立得到的 `checkpoint_sha256` 替换 `CHECKPOINT_SHA`。完整精简证明核对包含路径、签发时有效的公钥以及对应的认定规则，然后重新计算学分。输出的 `height` 是原回执区块高度，`checkpoint_height` 是此次可信历史快照的高度。检查点之后的新提交可通过增量审计纳入更新后的快照。

```bash
educreditlab verify ./review.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA
```

工作台的**存证与回放**支持这两种精简证明。导入文件，填入信任清单指纹，展开检查点字段并填入独立核定的指纹。首次建立检查点需要核验完整历史，此项成本与逐份回执核验分别测量。精简完整版的大小也取决于同一政策范围内的登记数量。

## 审核新增区块

以下示例从第 4 区块更新至第 6 区块。使用新工作目录运行 `demo-revision`，清单指纹可从 `revision-output/trusted-manifest-sha256.txt` 取得。

```bash
educreditlab --workspace ./revision-study demo-revision --out ./revision-output
educreditlab --workspace ./revision-study checkpoint export --height 4 --out ./archive-4.json.gz
educreditlab checkpoint audit ./archive-4.json.gz --trust MANIFEST_SHA --archive-out ./audited-4.json.gz
educreditlab --workspace ./revision-study checkpoint export --from-height 4 --height 6 --out ./delta-4-6.json.gz
educreditlab checkpoint extend ./audited-4.json.gz ./delta-4-6.json.gz --trust MANIFEST_SHA --archive-trust ARCHIVE_SHA --expect-height 6 --archive-out ./audited-6.json.gz
```

用独立审计输出的 `archive_sha256` 替换 `ARCHIVE_SHA`。这是公开档案的规范 JSON 摘要。核验方需和来件分开保存该值。精简回执使用 `checkpoint_sha256`。这两个指纹各有用途。

更新包只包含基准高度、基准链头、清单摘要和新增的签名区块。核验方先校验原档案指纹，再还原政策与生效公钥，逐块确认新增记录的链接、签名和登记顺序。回执索引和 Merkle 根按更新后的历史推导。命令的 `verified_new_blocks` 字段给出此次重新验签的区块数。已知目标链头时可加 `--expect-head`。留存 `audited-6.json.gz` 和本次输出的新档案指纹即可继续更新。

增量审计包括读取与校验留存档案以及重建索引。应分别记录新增区块的传输量、审计耗时和随后的单份回执核验耗时。更新包界定所提交的区块范围，目标链头的预期值可用于确认收到指定版本。

随包 `results/checkpoint-extension/demo/` 提供上述合成实验的已审计第 4 区块档案、增量更新包和两份精简回执。复核该案例时，从 `base-audit.json` 取得初始 `checkpoint.manifest_sha256` 和 `archive_sha256`，分别作为 `MANIFEST_SHA` 和 `ARCHIVE_SHA`。运行增量命令后核对 `extended-audit.json` 的 `checkpoint_sha256`，用该值核验两份回执。

## 批量核验回执

指定同一检查点已有的各张回执摘要和已提交高度。用独立审计得到的信任清单和检查点指纹进行核验。每项 `--expect-receipt` 值来自核验方确认的收件清单，顺序不限。使用 `--anchor-only` 导出仅存证的版本。

```bash
educreditlab --workspace ./workbench bundle-batch RECEIPT_A RECEIPT_B --checkpoint-height H --out ./batch.json.gz
educreditlab verify ./batch.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA --expect-receipt RECEIPT_A --expect-receipt RECEIPT_B
```

完整版共享政策时间线、政策正文和 Merkle 路径。核验器对每张回执分别检查原有签发证据，并使用当时的政策和公钥复算学分。存证版只共享回执叶节点及其 Merkle 路径，适用于核对存证摘要。工作台显示文件中已成功核验的回执。清单完整性核对使用命令行参数。

`results/batch-proof/demo/` 提供三张回执的两种批量证明、公开审计档案、预期清单与合成样本指纹。可用合成用例初始清单指纹先独立审计该目录的 `public-history.json.gz`，再核验批量样本。实际收件时，档案、指纹与预期回执清单按各自信任流程取得。

## 按审核计划披露证据

审核方在一个已核验检查点上列出各项回执。需要复算的回执用 `--replay` 指定，只需确认存证的回执用 `--anchor` 指定。每个参数可重复添加，回执摘要须唯一。命令返回计划的规范 JSON SHA-256。导出方和审核方都从独立渠道取得并确认该指纹。

```bash
educreditlab review-plan --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA --replay RECEIPT_A --anchor RECEIPT_B --out ./plan.json
educreditlab --workspace ./workbench bundle-review ./plan.json --plan-trust PLAN_SHA --checkpoint-height H --out ./review.json.gz
educreditlab verify ./review.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA --plan-trust PLAN_SHA
```

审核计划绑定具体检查点。改用其他检查点、增减回执或调整复算范围时，双方重新核对计划指纹。导出方在读取私有证据前检查计划指纹和回执范围，随后只读取指定复算的成绩单与认定结果。核验方逐项检查收到的回执和证据，所有要求通过后才返回结果。存证项只证明对应回执承诺出现在指定检查点。完整复算项含原成绩证据，按院校授权范围传输。

`results/review-plan/demo/` 包含两条复算与一条存证的三回执合成案例。用 `pins.json` 的三个指纹可以验证 `review.json.gz`。该案例的原始公开档案在 `results/batch-proof/demo/public-history.json.gz`。可先核验该档案生成检查点，再对照 `plan.json` 复验审核范围。

## 签发和核验审核确认书

审核方使用独立生成的审核签名密钥。签发时，软件先用可信清单、检查点和计划指纹完成原证明核验，再签署确认书。确认书记录三项指纹、原证明的规范 JSON 摘要、核验结果摘要、签署时间和各项数量。它不携带成绩单、逐条认定结果或审核私钥。签署时间采用审核端时钟。

```bash
educreditlab review-keygen --key ./reviewer.pem
educreditlab review-attest ./review.json.gz --key ./reviewer.pem --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA --plan-trust PLAN_SHA --out ./attestation.json.gz
educreditlab verify-attestation ./attestation.json.gz --reviewer-trust REVIEWER_SHA --plan-trust PLAN_SHA
```

`REVIEWER_SHA` 为审核公钥原始字节的 SHA-256。签名核验方通过独立渠道获取认可的公钥指纹和计划指纹。签名核验验证审核方的声明。若要核对指定原证明，可另外指定 `--proof-trust`。原证明指纹按规范 JSON 计算，与 gzip 包装方式无关。

持有获准使用的原始证明时，可追加 `--proof ./review.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA` 独立复查。软件匹配原证明摘要，重新核验原证明，再比较签署结果摘要和统计项。只有复查成功才返回 `proof_rechecked: true`。工作台支持确认书签名核验。

`results/review-attestation/three/` 是 3 回执示例，原证明为 `results/review-plan/demo/review.json.gz`。`results/review-attestation/128/` 是 128 回执示例，原证明为 `results/review-plan/review-128.json.gz`。各目录的指纹仅用于合成样本。

## 多方审核确认书

审核规则指定已批准的审核计划、审核公钥指纹名单和最少有效签名数。各审核人在自己的设备上核验同一份原证明，再用各自的密钥执行 `review-attest`。汇集签名和核验确认书时，使用从独立渠道确认的审核规则指纹。

```bash
educreditlab review-quorum --plan-trust PLAN_SHA --reviewer-trust REVIEWER_A --reviewer-trust REVIEWER_B --reviewer-trust REVIEWER_C --threshold 2 --out ./policy.json
educreditlab bundle-quorum ./policy.json ./review-A.json.gz ./review-B.json.gz --policy-trust POLICY_SHA --out ./quorum.json.gz
educreditlab verify-quorum ./quorum.json.gz --policy-trust POLICY_SHA
```

`POLICY_SHA` 为规则规范 JSON 的 SHA-256，由创建命令返回。每个公钥计入一次。系统检查提交的全部签名，并核对原证明、检查点、计划、结果摘要和审核统计是否一致。可用 `--proof-trust` 核对指定的原证明摘要。持有获准使用的原证明时，添加下列参数可在签名核验后独立复查原证明一次。

```bash
educreditlab verify-quorum ./quorum.json.gz --policy-trust POLICY_SHA --proof ./review.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA
```

`results/review-quorum/three/` 和 `results/review-quorum/128/` 分别展示 2/3 与 3/4 公钥门槛。多方确认书包含名单、规则与签名摘要。两个案例分别使用 `results/review-plan/demo/review.json.gz` 和 `results/review-plan/review-128.json.gz` 作为原证据。签名核验确认已授权公钥的署名声明，机构负责确认公钥实际保管人与其独立性。

## 审核规则历史

同一审核计划下，可以更换审核公钥或修改签名门槛。先用 `review-quorum` 生成初始规则与拟变更的规则。为初始规则建立历史时，采用独立确认的初始规则指纹。第一版的版本指纹等于初始规则指纹。

```bash
educreditlab policy-history init ./initial-policy.json --policy-trust INITIAL_SHA --out ./history-r1.json.gz
educreditlab policy-history approve ./history-r1.json.gz ./successor-policy.json --initial-trust INITIAL_SHA --revision-trust INITIAL_SHA --key ./reviewer-A.pem --out ./approval-A.json
```

其他审核人使用自己的密钥重复签署，所有人核对同一份待签规则和前序版本。签名公钥必须分别达到旧名单和新名单的门槛。公钥同时属于两个名单时，可各计一次。以下示例汇集三份审批，实际所需的签名组合由两版规则共同决定。

```bash
educreditlab policy-history append ./history-r1.json.gz ./successor-policy.json ./approval-A.json ./approval-B.json ./approval-C.json --initial-trust INITIAL_SHA --revision-trust INITIAL_SHA --out ./history-r2.json.gz
educreditlab policy-history verify ./history-r2.json.gz --initial-trust INITIAL_SHA --revision-trust R2_SHA
```

`R2_SHA` 对应 `append` 输出的 `latest_revision_sha256`。由业务接收方从独立渠道核实预期最新版本，再比对所收文件。只掌握较早版本指纹时，最多能核实该版本，获取已发布最新版本由机构流程负责。发布后续变更时，把上一步已独立确认的版本指纹传给 `approve` 和 `append`。

下面使用三版样本核验旧、新两份确认书。先从 `results/review-policy-history/128/pins.json` 取得合成样本中的 `initial_policy_sha256` 和 `latest_revision_sha256`，并替换命令中的 `INITIAL_SHA` 和 `LATEST_SHA`。

```bash
educreditlab policy-history review results/review-policy-history/128/history.json.gz results/review-policy-history/128/historical-quorum.json.gz --initial-trust INITIAL_SHA --revision-trust LATEST_SHA --revision 1
educreditlab policy-history review results/review-policy-history/128/history.json.gz results/review-policy-history/128/current-quorum.json.gz --initial-trust INITIAL_SHA --revision-trust LATEST_SHA
```

指定 `--revision` 后仍会先核验整条历史及预期末端。省略该参数时使用已核验的末端规则。若持有合规取得的原证明，可加上 `--proof FILE --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA` 独立复查。旧格式签名覆盖证明与审核计划，结果中 `revision_binding_verified` 为 `false`，表示核验了所选规则的适用性。

## 绑定规则版本的审核确认书

审核人先从独立渠道取得初始规则和预期最新版本的指纹。签发命令核验整个规则历史、当前名单和原证明，再把当前规则版本的指纹写入签名正文。审核计划取自已核准的规则。不同审核人在各自设备使用各自保管的密钥。

```bash
educreditlab policy-history attest ./history.json.gz ./review.json.gz --initial-trust INITIAL_SHA --revision-trust LATEST_SHA --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA --key ./reviewer-A.pem --out ./review-A.json.gz
educreditlab policy-history bundle ./history.json.gz ./review-A.json.gz ./review-B.json.gz ./review-C.json.gz --initial-trust INITIAL_SHA --revision-trust LATEST_SHA --out ./bound-quorum.json.gz
educreditlab policy-history review ./history.json.gz ./bound-quorum.json.gz --initial-trust INITIAL_SHA --revision-trust LATEST_SHA --require-revision-binding
```

上例收集三份签名，实际签名数量由核验版本的门槛决定。对于历史确认书，汇集和核验时均可指定 `--revision N`，并仍使用独立确认的最新版本指纹。成功时返回 `revision_binding_verified: true`。需要另外核验原始证据时，增加 `--proof FILE --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA`。审核人签名中的时间为其本地报告时间。机构负责发布预期最新版本指纹以及需要的独立时间凭证。

`results/revision-bound-review/128/` 同时提供历史确认书、当前确认书、旧格式对照和配套指纹。该合成样本在第 3 版恢复初始规则，原名单和签名门槛完全一致，但适用的签名版本不同。使用工作台时，选择**绑定规则版本的审核确认书**，同时导入规则历史和多方确认书。

## 审核规则分歧证据

比较从同一初始规则出发的两条历史时，提供独立确认的初始规则指纹及两份档案各自预期的末端指纹。系统逐份核验签名和门槛，再按版本指纹比较共同前缀。返回 `identical`、`left_prefix`、`right_prefix` 或 `diverged`，并报告最后一个共同版本。同一变更有多组有效签名时，其版本指纹相同。

```bash
educreditlab policy-history compare ./left.json.gz ./right.json.gz --initial-trust INITIAL_SHA --left-trust LEFT_SHA --right-trust RIGHT_SHA
educreditlab policy-history compare ./left.json.gz ./right.json.gz --initial-trust INITIAL_SHA --left-trust LEFT_SHA --right-trust RIGHT_SHA --out ./divergence.json.gz
educreditlab policy-history verify-divergence ./divergence.json.gz --initial-trust INITIAL_SHA
```

当比较结果为 `diverged` 时可指定 `--out`。证据只需保存一次共同前缀，再保存两份各自通过授权的首个分歧变更。第三方可凭独立可信的初始规则指纹复核共同前缀和这两份签名。结果中 `shared_predecessor_approvers` 列出共同前序名单内同时签署两项变更的公钥指纹。机构根据保管与审批记录判断这些签名的业务含义并决定采用的规则。

`results/policy-divergence/short/` 和 `long/` 提供两套完整历史与各自的 `pins.json`。使用目录内 `left.json.gz` 和 `right.json.gz`，依次将 `initial_policy_sha256`、`left_latest_revision_sha256`、`right_latest_revision_sha256` 填入上述命令。两套历史在第 3 版出现同一分歧，导出的 `evidence_sha256` 相同。对任一完整历史的现行状态，应使用对应末端指纹核验。离线证据适用于确认证据所含首处分歧。

## 审核规则分歧裁定书

机构先确认采用的分支和确切末端版本，并认可裁定签名公钥名单与门槛。以下示例使用两份有效签名作为门槛。可使用 `review-keygen` 生成演示裁定密钥。业务使用时，通过院校认可的途径核实公钥归属，并向接收方独立公布裁定权限指纹及生效裁定正文指纹。

```bash
educreditlab policy-history resolution-authority --initial-trust INITIAL_SHA --resolver-trust KEY_A --resolver-trust KEY_B --resolver-trust KEY_C --threshold 2 --out ./authority.json
educreditlab policy-history resolution-sign ./authority.json ./divergence.json.gz ./selected-history.json.gz --authority-trust AUTHORITY_SHA --selected-trust SELECTED_SHA --key ./resolver-A.pem --out ./approval-A.json
educreditlab policy-history resolution-sign ./authority.json ./divergence.json.gz ./selected-history.json.gz --authority-trust AUTHORITY_SHA --selected-trust SELECTED_SHA --key ./resolver-B.pem --out ./approval-B.json
educreditlab policy-history resolution-bundle ./authority.json ./divergence.json.gz ./selected-history.json.gz ./approval-A.json ./approval-B.json --authority-trust AUTHORITY_SHA --selected-trust SELECTED_SHA --out ./resolution.json.gz
educreditlab policy-history verify-resolution ./resolution.json.gz --authority-trust AUTHORITY_SHA --decision-trust DECISION_SHA
```

每位裁定人签署同一份正文。正文承诺裁定权限、分歧证据、选中的直接后续版本及所选历史的确切末端。签发时独立核对 `SELECTED_SHA`。汇集命令输出的 `decision_sha256` 与已发布裁定正文指纹对应。若院校确认采用新末端，按新的确切版本签发裁定。

在 `results/policy-resolution/long/` 内可用随附指纹验算合成裁定。使用 `--review` 还能核验绑定所选版本的审核确认书。若有合规取得的原始证明，添加 `--proof` 及相应清单和检查点指纹。

```bash
educreditlab policy-history verify-resolution ./resolution.json.gz --authority-trust AUTHORITY_SHA --decision-trust DECISION_SHA --review ./joint.json.gz --proof ./review.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA
```

采用哪条历史由机构决定。软件检查收到的裁定是否匹配独立确认的权限、正文和签名，并可核验其所选版本的审核确认书。

## 院校裁定发布历史

同一份分歧证据下，院校可依次发布多份已签署裁定书。发布签名承诺历史起点、发布序号、前一发布记录和本次裁定正文指纹。恢复采用原裁定时，也须对新的发布序号和前序重新签名。裁定发布序号与裁定书中选定的审核规则版本各有自己的指纹。

```bash
educreditlab resolution-history init ./authority.json ./divergence.json.gz --authority-trust AUTHORITY_SHA --out ./history-start.json.gz
educreditlab resolution-history sign ./history-start.json.gz ./resolution.json.gz --authority-trust AUTHORITY_SHA --publication-trust PRIOR_SHA --decision-trust DECISION_SHA --key ./resolver-A.pem --out ./publish-A.json
educreditlab resolution-history sign ./history-start.json.gz ./resolution.json.gz --authority-trust AUTHORITY_SHA --publication-trust PRIOR_SHA --decision-trust DECISION_SHA --key ./resolver-B.pem --out ./publish-B.json
educreditlab resolution-history append ./history-start.json.gz ./resolution.json.gz ./publish-A.json ./publish-B.json --authority-trust AUTHORITY_SHA --publication-trust PRIOR_SHA --decision-trust DECISION_SHA --out ./history.json.gz
educreditlab resolution-history verify ./history.json.gz --authority-trust AUTHORITY_SHA --publication-trust LATEST_SHA
```

首次发布时，`PRIOR_SHA` 取初始化输出的 `latest_publication_sha256`。下次签发时，使用经独立确认的前序末端和对应历史文件。接收方通过独立渠道确认权限指纹和当前发布末端，用这两项信任材料验证历史。单独核验历史可确认发布次序与当前裁定指纹。检查某份裁定的内容、签名和对应审核确认书时，另载入保存的裁定书。

```bash
educreditlab resolution-history review ./history.json.gz ./resolution.json.gz --authority-trust AUTHORITY_SHA --publication-trust LATEST_SHA
educreditlab resolution-history review ./history.json.gz ./old-resolution.json.gz --authority-trust AUTHORITY_SHA --publication-trust LATEST_SHA --publication 2 --review ./old-quorum.json.gz --proof ./review.json.gz --trust MANIFEST_SHA --checkpoint-trust CHECKPOINT_SHA
```

默认核验最新发布。复核历史记录时仍以当前已确认的末端为准，再用 `--publication` 指定序号。每组发布历史对应一份已核准分歧展件和裁定权限。实际审批与末端公布由院校负责。

`results/resolution-history/` 收录 `first-resolution.json.gz`、`second-resolution.json.gz` 及不同长度的发布历史。第一次发布采用第一份裁定，第二次改用第二份，第三次恢复第一份。用 `long/pins.json` 核验 27 项发布。历史审查样本的原确认书在 `results/policy-divergence/long/right-quorum.json.gz`，对应第二次发布。原证明为 `results/review-plan/review-128.json.gz`。

## 院校裁定权限交接

交接记录同时确认接任权限并发布其签发的第一份裁定书，占用一个发布序号。交出方和接任方各自达到本方门槛后方可汇集。以下示例包含两份交出方签名和三份接任方签名。先使用 `policy-history resolution-authority` 生成接任权限，再用该权限签发裁定书。

```bash
educreditlab resolution-history handover-sign ./prior-history.json.gz ./incoming-resolution.json.gz ./incoming-authority.json --authority-trust INITIAL_SHA --publication-trust PRIOR_SHA --decision-trust DECISION_SHA --successor-trust INCOMING_SHA --role outgoing --key ./outgoing-A.pem --out ./out-A.json
educreditlab resolution-history handover-sign ./prior-history.json.gz ./incoming-resolution.json.gz ./incoming-authority.json --authority-trust INITIAL_SHA --publication-trust PRIOR_SHA --decision-trust DECISION_SHA --successor-trust INCOMING_SHA --role incoming --key ./incoming-A.pem --out ./in-A.json
educreditlab resolution-history handover-append ./prior-history.json.gz ./incoming-resolution.json.gz ./incoming-authority.json --authority-trust INITIAL_SHA --publication-trust PRIOR_SHA --decision-trust DECISION_SHA --successor-trust INCOMING_SHA --outgoing ./out-A.json ./out-B.json --incoming ./in-A.json ./in-B.json ./in-C.json --out ./history.json.gz
```

后续 `resolution-history sign`、`append`、`verify` 和 `review` 继续使用独立确认的初始权限指纹以及对应的发布末端指纹。软件沿已签署的交接记录确定生效权限。审核历史裁定时，`verified_authority_sha256` 显示所选发布记录的签发权限，`active_authority_sha256` 显示当前权限。历史序号和信任起点可由旧版历史直接接续。

`results/resolution-handover/` 中的 `prior-history.json.gz` 是交接前的历史。`outgoing-resolution.json.gz` 对应第 1 次发布，`incoming-resolution.json.gz` 对应第 2 次及后续发布。复核历史确认书和当前确认书可分别使用 `results/policy-divergence/long/left-quorum.json.gz` 和 `right-quorum.json.gz`。权限定期交接依赖两方签名和院校认可的末端发布。

## 裁定发布检查点

先用独立确认的初始权限和预期末端指纹审计完整的签名发布历史，再生成检查点和指定发布的证明。检查点记录该分歧的范围、末端发布、发布条数和 Merkle 根。末端代表该检查点覆盖到的位置。若需确定某一时点的最新裁定，应通过独立可信渠道确认当时有效的检查点指纹。

```bash
educreditlab resolution-history checkpoint ./history.json.gz --authority-trust INITIAL_SHA --publication-trust HEAD_SHA --out ./publication-checkpoint.json --witness-out ./archived-witness.json.gz --publication 1
educreditlab resolution-history checkpoint-verify ./archived-witness.json.gz --publication-checkpoint-trust PUBLICATION_CHECKPOINT_SHA --publication 1
```

将审计方通过独立渠道提供的 `publication_checkpoint_sha256` 用作 `PUBLICATION_CHECKPOINT_SHA`。验证时省略 `--publication` 默认核验检查点的末条，选择历史记录时须明确序号。工作台可验证这份包含证明，有联合确认书和原始证据的读者可继续通过命令行复核裁定。下例使用的 `RECEIPT_CHECKPOINT_SHA` 是回执账本检查点指纹。

```bash
educreditlab resolution-history checkpoint-verify ./archived-witness.json.gz --publication-checkpoint-trust PUBLICATION_CHECKPOINT_SHA --publication 1 --resolution ./outgoing-resolution.json.gz --review ./left-quorum.json.gz --proof ./review-128.json.gz --trust MANIFEST_SHA --checkpoint-trust RECEIPT_CHECKPOINT_SHA
```

样本 `results/resolution-checkpoint/long/` 含检查点描述、演示指纹、第一条与末条的证明。对应的签名历史与裁定书在 `results/resolution-handover/`，联合确认书在 `results/policy-divergence/long/`，原始计划回执证明在 `results/review-plan/`。两种证明各自固定所属快照。

## 接续裁定发布检查点

发布方先审计最新完整历史，再从已知基线之后导出新增签名记录。复核方保留原检查点的可信指纹和末端证明。下例从第 1,023 条接续到第 1,031 条。发布方用独立确认的初始权限指纹替换 `INITIAL_SHA`，双方用独立确认的目标末端发布指纹替换 `LATEST_SHA`，复核方用原来核准的检查点指纹替换 `BASE_CHECKPOINT_SHA`。

```bash
educreditlab resolution-history checkpoint-delta ./history.json.gz --from-publication 1023 --authority-trust INITIAL_SHA --publication-trust LATEST_SHA --out ./delta.json.gz
educreditlab resolution-history checkpoint-extend ./base-witness.json.gz ./delta.json.gz --publication-checkpoint-trust BASE_CHECKPOINT_SHA --publication-trust LATEST_SHA --out ./advanced-witness.json.gz
educreditlab resolution-history checkpoint-verify ./advanced-witness.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA
```

复核方使用原末端证明重新核对基线的序号、发布指纹和当时生效的权限。软件验证新增记录的顺序、链接和签名，遇到交接时分别核对双方门槛。输出的 `publication_checkpoint_sha256` 是 `ADVANCED_CHECKPOINT_SHA`，可和新末端证明一起保留以便下次接续。

完整示例在 `results/resolution-checkpoint-extension/long/`。其中 `pins.json` 的 `base_checkpoint_sha256`、`latest_publication_sha256` 和 `advanced_checkpoint_sha256` 可分别用于演示上述指纹。首条新增记录执行权限交接。更新后可在工作台选择「院校裁定发布证明」核验新末端证明。

## 更新历史裁定证明

复核方用同一原检查点指纹核验已保存的历史证明和原末端证明，再接续同一份签名增量。命令要求明确历史发布序号，并使用独立确认的新末端发布指纹。下例把第 1 次裁定发布的证明更新至覆盖 1,031 次发布的检查点。

```bash
educreditlab resolution-history checkpoint-refresh ./base-witness.json.gz ./delta.json.gz ./archived-witness.json.gz --publication 1 --publication-checkpoint-trust BASE_CHECKPOINT_SHA --publication-trust LATEST_SHA --out ./refreshed-witness.json.gz
educreditlab resolution-history checkpoint-verify ./refreshed-witness.json.gz --publication 1 --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA
```

从 `results/resolution-checkpoint-extension/long/` 取得演示的末端证明和增量，从 `results/resolution-witness-refresh/long/` 取得原历史证明及演示指纹。更新后的历史证明与新末端证明使用相同的检查点指纹。要完整复核历史裁定，可在第二条命令加 `--resolution`、`--review` 和对应的原始证据参数。第 1 次发布仍按当时生效的权限核验。下一次接续可保存本次产生的历史证明及同检查点的新末端证明。若没有留存历史证明，可从完整历史导出所需序号。

## 批量裁定发布证明

先从已审计的基线历史导出所需发布序号的批量证明。更新时提交原检查点末端证明、签名增量和原批量证明。每条命令均用重复的 `--publication` 提供完整预期序号集合。软件对整组核验，并拒绝遗漏、重复和替换的序号。下例选择第 1 次和第 5 次发布。

```bash
educreditlab resolution-history checkpoint-batch ./base-history.json.gz --authority-trust INITIAL_SHA --publication-trust BASE_HEAD_SHA --publication 1 --publication 5 --out ./base-batch.json.gz
educreditlab resolution-history checkpoint-refresh-batch ./base-head.json.gz ./delta.json.gz ./base-batch.json.gz --publication-checkpoint-trust BASE_CHECKPOINT_SHA --publication-trust LATEST_SHA --publication 1 --publication 5 --out ./refreshed-batch.json.gz
educreditlab resolution-history checkpoint-verify-batch ./refreshed-batch.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 5
```

要复核批量中的某份裁定书，可在最后一条命令加 `--select-publication 1 --resolution ./outgoing-resolution.json.gz`，并按需加上联合确认书和原始回执证据参数。第 1 次发布仍按其发布时的权限核验。工作台的「批量裁定发布证明」可查看整组发布的核验结果。

在 `results/resolution-batch/handover/` 和 `results/resolution-batch/mixed/` 可复验 8 条与 32 条历史发布的更新。演示所需的基线证据、增量和更新后的证明随包提供。序号及指纹见各目录的 `pins.json`。

## 从批量证明提取指定发布

提取命令先核验原批量证明的完整预期序号集合和可信检查点。重复 `--publication` 填原集合，重复 `--select-publication` 填要交付的子集。以下命令从 `results/resolution-batch/handover/refreshed-batch.json.gz` 的 8 条发布中提取第 1 次和第 31 次发布。用该用例的 `advanced_checkpoint_sha256` 替换演示指纹。

```bash
educreditlab resolution-history checkpoint-select-batch ./refreshed-batch.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --select-publication 1 --select-publication 31 --out ./subset.json.gz
educreditlab resolution-history checkpoint-verify-batch ./subset.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 31
```

若只指定一条，可加 `--single` 生成单条证明，并用 `checkpoint-verify --publication N` 核验。子集继续使用原检查点指纹，其中每条裁定保留各自发布时生效的权限。工作台可按批量或单条类型验证生成的文件。演示用例在 `results/resolution-selection/`。

## 在同一检查点合并裁定证明

合并前需要独立确认检查点指纹与预期合并的全部发布序号。程序逐份验证文件，合并后按序号排序并去除相同记录的重叠。结果必须恰好覆盖指定集合。不同检查点的证明可先更新到共同检查点，再执行合并。

以下示例使用 `results/resolution-merge/handover/` 中的四份证明。用该目录 `pins.json` 的 `advanced_checkpoint_sha256` 替换演示指纹。

```bash
educreditlab resolution-history checkpoint-merge-batch ./source-1.json.gz ./source-2.json.gz ./source-3.json.gz ./source-4.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --out ./merged.json.gz
educreditlab resolution-history checkpoint-verify-batch ./merged.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31
```

合并后的标准批量证明可在工作台核验，也可继续用于裁定书和原始回执复查。覆盖两套发布权限的完整示例位于 `results/resolution-merge/mixed/`。

## 合并检查点更新前后的裁定证明

审核方先确认基线检查点指纹、预期的新末端发布指纹及合并后的全部发布序号。提交基线末端证明、签名增量和各组保留的单条或批量证明。命令验证一次增量，检查权限交接双方的签名门槛，并计算新检查点。然后分别验证两个检查点的输入，在基线合并并更新旧证明，再与已在新检查点的证明合并。每条裁定沿用其发布时的权限，输出仅包含预期集合中的发布。

从 `results/resolution-advance-merge/handover/` 取得输入并在该目录执行以下命令。用 `pins.json` 的 `base_checkpoint_sha256`、`latest_publication_sha256` 和 `advanced_checkpoint_sha256` 替换对应指纹。基线末端证明和增量位于 `../../resolution-checkpoint-extension/short/`。

```bash
educreditlab resolution-history checkpoint-advance-merge-batch ../../resolution-checkpoint-extension/short/base-witness.json.gz ../../resolution-checkpoint-extension/short/delta.json.gz ./base-1.json.gz ./base-2.json.gz ./base-3.json.gz ./base-4.json.gz ./advanced-1.json.gz ./advanced-2.json.gz --publication-checkpoint-trust BASE_CHECKPOINT_SHA --publication-trust LATEST_SHA --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --publication 32 --publication 33 --publication 39 --out ./combined-rebuilt.json.gz
educreditlab resolution-history checkpoint-verify-batch ./combined-rebuilt.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --publication 32 --publication 33 --publication 39
```

输入支持基线和增量推导出的两个检查点。持有其他检查点证明的审核组可先验证相应的续接关系并更新其证明。输出是标准批量证明，可交给工作台核验，也可在 CLI 中选定条目复查裁定书及回执证据。

## 从签名增量导出新增裁定证明

重复 `--include-new-publication N` 指定要从增量导出的发布。序号必须大于基线发布数，且已包含在签名增量中。仍须单独用 `--publication N` 指定最终预期的完整集合。程序验证一次签名增量，以基线末端路径中的旧子树和增量中的已验发布重建证明。输出只包含指定的条目和重建根所需的邻接哈希。

在 `results/resolution-advance-merge/handover/` 运行下例，用该目录 `pins.json` 中的三个指纹替换占位符。第 32、33 和 39 次发布直接从增量导出，第 1 至 31 次中指定的八条发布使用四份基线证明。

```bash
educreditlab resolution-history checkpoint-advance-merge-batch ../../resolution-checkpoint-extension/short/base-witness.json.gz ../../resolution-checkpoint-extension/short/delta.json.gz ./base-1.json.gz ./base-2.json.gz ./base-3.json.gz ./base-4.json.gz --publication-checkpoint-trust BASE_CHECKPOINT_SHA --publication-trust LATEST_SHA --include-new-publication 32 --include-new-publication 33 --include-new-publication 39 --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --publication 32 --publication 33 --publication 39 --out ./derived-combined.json.gz
educreditlab resolution-history checkpoint-verify-batch ./derived-combined.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --publication 32 --publication 33 --publication 39
```

若只交付新增裁定，可去掉四份基线输入证明，并把 `--publication` 缩减为第 32、33 和 39 次发布。样例输出 `suffix-only.json.gz` 和合并输出 `combined.json.gz` 位于 `results/resolution-suffix-proof/handover/`，对应的大型样例位于同级的 `mixed/`。

## 合并多段增量中的裁定证明

使用 `checkpoint-chain-merge-batch` 处理连续发布的签名增量。先确认基线检查点指纹、每段预期的末端发布指纹及最终预期的所有发布序号。按时间顺序重复 `--step 增量文件 预期末端指纹`。后一段必须接续前一段的末端，并采用当时有效的发布权限。程序逐段核验，再按来源检查点验证证明，把各组证明各更新一次到最终检查点。也可通过 `--include-new-publication N` 直接选取增量中的新增发布。

在 `results/resolution-checkpoint-chain/handover/` 执行下例。将占位符换为 `pins.json` 的 `base_checkpoint_sha256`、依序列出的两个 `stage_publication_sha256`，以及 `advanced_checkpoint_sha256`。第 2、33 次发布来自第 34 次发布处留存的证明，第 39 次发布来自最终检查点。第 32、38 次发布直接从两段增量导出。

```bash
educreditlab resolution-history checkpoint-chain-merge-batch ../../resolution-checkpoint-extension/short/base-witness.json.gz ../../resolution-advance-merge/handover/base-1.json.gz ../../resolution-advance-merge/handover/base-2.json.gz ../../resolution-advance-merge/handover/base-3.json.gz ../../resolution-advance-merge/handover/base-4.json.gz ./intermediate.json.gz ./final.json.gz --publication-checkpoint-trust BASE_CHECKPOINT_SHA --step ./delta-1.json.gz FIRST_TIP_SHA --step ./delta-2.json.gz FINAL_TIP_SHA --include-new-publication 32 --include-new-publication 38 --publication 1 --publication 2 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --publication 32 --publication 33 --publication 38 --publication 39 --out ./chain-rebuilt.json.gz
educreditlab resolution-history checkpoint-verify-batch ./chain-rebuilt.json.gz --publication-checkpoint-trust ADVANCED_CHECKPOINT_SHA --publication 1 --publication 2 --publication 5 --publication 9 --publication 13 --publication 17 --publication 21 --publication 25 --publication 31 --publication 32 --publication 33 --publication 38 --publication 39
```

可将同目录的 `combined.json.gz` 提交工作台核验，并用 `pins.json` 填写最终检查点指纹和预期序号。软件接受基线及每段末端检查点的证明。如需合并在段内其他检查点签发的证明，应在该检查点处分段并提供对应指纹。

v1.26.0 按最终 Merkle 树中的层级与位置复用变动的相邻子树根。复用仅用于一次合并内的证明刷新。程序先逐段认证签名和末端指纹，再核验每个来源证明及最终批量证明。不同版本的对照数据见 `results/resolution-refresh-reuse/`。

v1.27.0 在核验每段签名增量后，复用追加阶段按顺序生成的叶哈希。刷新旧证明以及构造指定新增发布的证明时都使用这些本次合并内生成的哈希。所有来源证明仍从原条目计算叶哈希，刷新结果和最终证明均重新校验 Merkle 根。

v1.28.0 的命令行在核验某一阶段时才读取该段增量文件。每段核验完成后，软件只保留后续构造证明用的精简发布条目和叶哈希，以及该阶段的末端证明。总内存还随精简条目、哈希和来源证明的数量变化。所有阶段和来源证明通过后才发布合并结果。

## 复验原始测量

`results/checkpoint-audit/` 包含 v1.5.0 在 512、2,048 和 10,000 区块的原始时延样本。同一回执的原版和精简版均使用 gzip。每个样本包括解码、核验和复算，核验计时从文件字节已读入后开始。完整前缀格式每组测三次，精简格式每组测三十次，首次检查点审计另测一次。

```bash
python tests/integration/checkpoint_audit.py results/long-history/synthetic-10000-proof.json.gz --trust MANIFEST_SHA --out-dir ./checkpoint-results
```

随包 `results/long-history/synthetic-10000-fingerprint.txt` 提供合成用例的初始清单指纹。对应精简样例的两项指纹均在 `results/checkpoint-audit/height-10000/`。常规完整前缀证明可直接用清单指纹核验。旧版工作区可使用同一账本生产这两种输出。

`results/checkpoint-extension/measurement.json` 记录 v1.6.0 达到同一链头的全量审计和增量审计。构建输入和建立基准档案信任不计时。全量审计和增量审计都从已读入的压缩字节开始。增量计时包含解码新旧文件、校验基准档案摘要、验签新增区块和重建检查点。可用同一源文件重跑。

```bash
python tests/integration/checkpoint_extension.py results/long-history/synthetic-10000-proof.json.gz --trust MANIFEST_SHA --out ./extension-measurement.json
```

`results/batch-proof/measurement.json` 记录 v1.7.0 的 8、32 和 128 张回执用例。每组使用相同的回执和同一检查点，对比各自 gzip 压缩的单份证明、合为一个 JSON 数组后统一 gzip 压缩的单份证明，以及批量证明。计时从压缩字节读入内存后开始，各测五次。统一压缩的数组用于体积对照。下列命令生成新签名的同规模合成样本并重跑对照实验。

```bash
python tests/integration/batch_proof_audit.py --out-dir ./batch-measurements
```

`results/review-plan/measurement.json` 记录同一检查点下 128 份回执的四种披露组合。对照组把复算项与存证项分别打包，双方使用相同的回执和复算要求。每组测五次解压、解析和核验。计时起点为文件字节已经读入内存。随包 `review-128.json.gz` 对应其中 16 条复算与 112 条存证。下列命令生成新签名的同规模样本并复跑。

```bash
python tests/integration/review_plan_audit.py --out-dir ./review-measurements
```

`results/review-attestation/measurement.json` 记录两个用例的 gzip 体积和核验耗时。每个模式测 21 次，计时从压缩字节已读入内存开始。签名核验和原证明复查分别计量。可按下列命令用新生成的测试密钥重跑。

```bash
python tests/integration/review_attestation_audit.py --out-dir ./attestation-measurements
```

`results/review-quorum/measurement.json` 保存多方确认书的压缩体积和核验耗时。每种模式测 21 次，计时从压缩文件字节读入内存开始。以下命令生成新的测试密钥并重跑。

```bash
python tests/integration/review_quorum_audit.py --out-dir ./quorum-measurements
```

`results/review-policy-history/measurement.json` 保存 3 份和 128 份回执的规则历史样本、校验结果与测量。每种模式从压缩字节已读入内存开始，计时 21 次。复验脚本在内存生成新的测试密钥，核对双门槛、历史版本、回退识别及原始证据复算。

```bash
python tests/integration/review_policy_history_audit.py --out-dir ./policy-history-measurements
```

`results/revision-bound-review/measurement.json` 保存 v1.12.0 的同规则复用实验。第 1 版和第 3 版使用相同的审核名单、门槛、签名公钥及原始证据。三种核验方式各测 21 次，计时包含解码和核验，读盘及签发不计入。

```bash
python tests/integration/revision_review_audit.py --out-dir ./revision-review-measurements
```

`results/policy-divergence/measurement.json` 对照完整历史比较与独立分歧证据核验。两组共用一个合成审核计划和首次分歧，区别是分歧后的历史长度。各模式计时 21 次，包含从内存解压及核验。

```bash
python tests/integration/policy_divergence_audit.py --out-dir ./divergence-measurements
```

`results/policy-resolution/measurement.json` 记录裁定书和审核确认书的复核耗时。两组使用相同的分歧证据和裁定名单。每种核验测 21 次，包含从内存解压及校验。脚本在内存重新生成裁定测试密钥。

```bash
python tests/integration/policy_resolution_audit.py --out-dir ./resolution-measurements
```

`results/resolution-history/measurement.json` 比较两种发布历史长度，复验历史签名、历史裁定适用性和原证据。每组测 21 次，从内存读取压缩文件字节开始。裁定书文件和发布历史的压缩体积分别记录。

```bash
python tests/integration/resolution_history_audit.py --out-dir ./publication-measurements
```

`results/resolution-handover/measurement.json` 比较含一次交接的 3 项和 27 项发布历史。每种核验独立测 21 次，从已读入内存的 gzip 文件字节开始。

```bash
python tests/integration/resolution_handover_audit.py --out-dir ./handover-measurements
```

`results/resolution-checkpoint/measurement.json` 复用上轮固定样本，分别记录完整发布历史核验、发布检查点构建、单条包含路径验证，以及搭配相同裁定书和联合确认书的对照结果。各项计时从内存中的 gzip 字节开始，原始回执证据另行复核。

```bash
python tests/integration/resolution_checkpoint_audit.py --source ./results --out-dir ./publication-checkpoint-measurements --repeats 21
```

`results/resolution-checkpoint-extension/measurement.json` 记录 31 和 1,023 条发布的基线，各接续 8 条记录。完整审计和接续均从内存中的 gzip 字节开始并生成相同的末端证明和检查点指纹。接续计时以已核准的基线为前提，导出增量和原始回执复查另行执行。

```bash
python tests/integration/resolution_checkpoint_extension_audit.py --source ./results --out-dir ./publication-extension-measurements --repeats 21
```

`results/resolution-witness-refresh/measurement.json` 记录同一签名增量下第 1 次发布证明的更新实测。两组比较均从内存中的 gzip 字节开始。增量更新计时覆盖两份原证明和增量的解压及核验，以已有可信基线为前提。原回执证据另行复查。

```bash
python tests/integration/resolution_witness_refresh_audit.py --source ./results --out-dir ./publication-refresh-measurements --repeats 21
```

`results/resolution-batch/measurement.json` 对比同一序号集合的完整审计、逐条更新和批量更新。逐条更新共用已解压的末端证据和签名增量，并为各条证明分别核验增量。输出体积比较将各独立证明组成一个 JSON 数组再统一 gzip 压缩。原始回执另行复查。

```bash
python tests/integration/resolution_batch_audit.py --source ./results --out-dir ./publication-batch-measurements --repeats 21
```

`results/resolution-selection/measurement.json` 对照同一子集用全量审计生成证明和从原批量提取证明。计时从各自的 gzip 字节开始，原批量证明的生成及原始回执复查另计。随包记录输入与输出的 gzip 体积。

```bash
python tests/integration/resolution_selection_audit.py --source ./results --out-dir ./publication-selection-measurements --repeats 21
```

`results/resolution-merge/measurement.json` 比较从四份既有证明合并和从完整签名历史生成同一序号集合。计时从各自的 gzip 字节开始。原证明的生成和原始回执复查另计。输出体积也与将四份证明放入一个 JSON 数组再统一 gzip 的结果对照。

```bash
python tests/integration/resolution_merge_audit.py --source ./results --out-dir ./publication-merge-measurements --repeats 21
```

`results/resolution-advance-merge/measurement.json` 记录同一历史上的四条操作路径。每条路径均从读入内存的 gzip 字节开始，源证明预先生成，原始回执复核另计。合并命令与三条基准路径均输出相同的批量证明。

```bash
python tests/integration/resolution_advance_merge_audit.py --source ./results --out-dir ./advance-merge-measurements --repeats 21
```

`results/resolution-suffix-proof/measurement.json` 比较完整审计、带预先签发证明的合并、更少输入文件的直接导出合并，以及只导出新增子集。每条路径的计时均从 gzip 字节已读入内存开始，原始回执复查另计。

```bash
python tests/integration/resolution_suffix_proof_audit.py --source ./results --out-dir ./suffix-proof-measurements --repeats 21
```

`results/resolution-checkpoint-chain/measurement.json` 比较完整审计、逐段使用单步合并的流程，以及直接合并多段增量。逐段流程使用已保存的中间末端证明，并以同一进程内的调用计时。三条路径均从 gzip 字节已读入内存开始，文件生成和原始回执复查另计。

```bash
python tests/integration/resolution_checkpoint_chain_audit.py --source ./results --out-dir ./checkpoint-chain-measurements --repeats 21
```

`results/resolution-refresh-reuse/measurement.json` 包含 4 段和 16 段增量的对照。两版读取同一组 gzip 输入并从内存中解码，分别运行 21 次。另运行一次统计 Merkle 叶哈希调用，计数不进入计时。完整审计用于生成和核对预期输出。下例中应将基线解释器路径指向独立安装了 v1.25.0 wheel 的 Python。省略该参数可单独复验当前安装版。

```bash
python tests/integration/resolution_refresh_reuse_audit.py --source ./results --out-dir ./refresh-reuse-measurements --baseline-python /path/to/v1.25.0-env/bin/python --repeats 21
```

`results/resolution-append-hashes/measurement.json` 使用同一套四段和十六段输入比较 v1.26.0 与 v1.27.0。四组试验以交替顺序运行两个安装版，每版在每组中预热一次并计时七次。计时从输入已读入内存开始，包含 gzip 解码和核验。另行记录叶哈希调用。将下例的解释器路径替换为独立安装了 v1.26.0 wheel 的 Python。

```bash
python tests/integration/resolution_append_hash_audit.py --source ./results --out-dir ./append-hash-measurements --baseline-python /path/to/v1.26.0-env/bin/python
```

`results/resolution-chain-memory/measurement.json` 对比 v1.27.0 和 v1.28.0 的命令行在同一组四段、十六段签名增量上的峰值常驻内存与耗时。两种分段均从第 31 次发布推进到第 16,415 次发布。脚本从交付的签名历史生成阶段增量与来源证明，并完整审计生成基准结果。每次试验使用新的 Linux 进程，交替运行两个版本。峰值常驻内存取进程的 `VmHWM`。计时包含读取文件、解码、核验和写出结果。脚本逐次核对输出与完整审计的压缩证明字节。

```bash
python tests/integration/resolution_chain_memory_audit.py --source ./results --out-dir ./chain-memory-trials --baseline-python /path/to/v1.27.0-env/bin/python --pairs 6
```
