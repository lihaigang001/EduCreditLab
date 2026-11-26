# EduCreditLab 中文快速上手

## 打开工作台

1. 安装 Python 3.11 或更新版本，将 ZIP 整包解压到可写目录。
2. Windows 双击 **Start_EduCreditLab.cmd**。首次安装需要下载 Python 依赖。看到工作台网址后打开 **http://127.0.0.1:8765**。保留命令窗口即可继续使用。
3. macOS 或 Linux 在解压目录运行以下命令。

       python3 -m venv .venv
       source .venv/bin/activate
       python -m pip install .
       educreditlab --workspace ./workbench serve

## 跑通三项操作

1. 在**认定对照**选“编程与微积分”。同一份合成成绩单在尔湾历史示例满足 2 项规则、16 个学季学分，在默塞德历史示例满足 6 项规则、20 个学期学分。展开任一条规则可检查课程组合、最低成绩和使用的证据。
2. 切换至**政策版本对照**并计算。模拟政策提高编程系列的最低成绩，原成绩单在新版示例下剩余 4 个学季学分可匹配。**政策库**展示两个真实历史摘录的原始链接和模拟版本的假设。
3. 在历史结果上点击**签发演示回执**。在**存证与回放**点击“回放”，或选择“完整回执（含成绩）”和“仅存证证明”。从签发工作台独立取得指纹后，用它核验导出的 JSON。完整版支持历史结果复算，存证版用于核验摘要和签名。

## 验证同一学年内的政策修订

在**认定对照**中选择**同日政策追溯**，点击**登记同学年修订示例**，再计算。保持认定日为 2023-06-15。编程成绩门槛的模拟修订使匹配学分从 16 个变为 4 个学季学分。将认定日改为 2023-05-31，两边都是 16 个学季学分。政策库可查看每版生效区间、登记区块、提交时间和所引用的父版本。

    educreditlab --workspace ./revision-study demo-revision --out ./revision-output

上面的命令生成两份回执和同日对照结果。可以分别核验两个视图，并查到认定时采用的区块高度。通过 `timeline` 可列出登记顺序。使用 `preview --known-height` 可指定某个已提交视图；`preview --known-at` 支持带时区的时间字串，例如 `2026-11-22T08:00:00Z`。请换成实际提交时间。

## 从旧版升级

关闭运行中的旧工作台，并备份原 `workbench` 目录。使用新版启动脚本时，将原工作区放在程序目录下，目录名为 `workbench`。脚本会安装 1.27.0 并使用该目录里的信任清单与现有账本。协调器打开旧工作区时会补建回执索引。使用自定义目录时，可通过 `--workspace` 指定原路径。旧登记记录的提案时间仍可查看，查询旧历史时可直接指定区块高度。

## 浏览长账本及压缩回执

**存证与回放**每页显示 40 个区块。点击**更早记录**或**上一页**浏览同一个已验证账本视图，点击**刷新到最新**取得新视图。回执可下载为原始 JSON、压缩完整回执或仅存证证明。上传前从签发方独立取得信任指纹。压缩证明超过浏览器的大小限制时，用 `educreditlab verify ./review.json.gz --trust 指纹` 核验。

## 在工作台验证精简证明

从 `results/checkpoint-audit/height-10000/` 选择 `compact-full-proof.json.gz`。在**存证与回放 → 验证导出的证明**处填入同目录的信任清单指纹，展开**使用检查点核验精简证明**，填入检查点指纹。通过后会显示第 10,000 区块及 16 个学季学分。随包指纹专供合成案例。实际核验需独立取得或建立可信检查点，详见 [检查点核验](docs/checkpoint-verification.md)。常规完整证明使用原有信任清单指纹，清空检查点字段即可按原方式核验。

要审核账本新增的区块，先在独立审计时用 `checkpoint audit --archive-out` 留存公开档案及输出的档案指纹。用 `checkpoint export --from-height` 取得更新包，然后运行 `checkpoint extend` 建立新检查点。使用新检查点指纹在工作台核验对应的精简证明。[检查点核验](docs/checkpoint-verification.md#审核新增区块)提供从第 4 区块更新至第 6 区块的命令。

## 在工作台核验一批回执

在 **存证与回放** 导入 `results/batch-proof/demo/full-batch.json.gz`。合成案例的信任清单指纹和检查点指纹都在同目录 `audit.json` 中，分别取 `checkpoint.manifest_sha256` 和 `checkpoint_sha256`。点击**验证并回放**，展开**批量回执明细**。三份回执依次来自尔湾原政策、尔湾模拟修订及默塞德历史政策，对应 16 个学季、4 个学季和 20 个学期学分。换用同目录的 `anchor-batch.json.gz` 可查看批量存证结果。需要核对收件名单时，用命令行的 `--expect-receipt` 指定每个预期回执摘要。

## 核验按审核计划导出的回执

在 **存证与回放** 导入 `results/review-plan/demo/review.json.gz`，使用同目录 `pins.json` 中的三个合成案例指纹。第 4 和第 6 区块的尔湾回执分别复算为 16 和 4 个学季学分。第 7 区块的默塞德回执只显示存证结果。展开**批量回执明细**查看每份的核验方式。实际业务中的计划及其指纹由审核方按独立渠道确认。核验单份或普通批量回执时清空计划指纹字段。命令行操作见 [按审核计划披露证据](docs/checkpoint-verification.md#按审核计划披露证据)。

## 核验审核确认书

在**存证与回放**将核验类型切换为**审核确认书**。导入 `results/review-attestation/three/attestation.json.gz`，从同目录的合成案例 `pins.json` 取 `reviewer_sha256` 和 `review_plan_sha256`，点击**验证审核确认书**。工作台应显示签名已核验，并显示签署记录中的 2 份复算与 1 份存证核验。实际业务中的审核公钥和计划指纹通过独立渠道确认。持有原始证明的审核人员可通过命令行 [复查原证明及签署结果](docs/checkpoint-verification.md#签发和核验审核确认书)。

## 核验多方审核确认书

在**存证与回放**选择**多方审核确认书**，导入 `results/review-quorum/128/quorum.json.gz`，从同目录的合成案例 `pins.json` 取 `policy_sha256`，点击**验证多方审核确认书**。合成案例应有 3 份有效签名，签名门槛为 3 份，记录 16 份复算与 112 份存证核验。实际业务中，接收方通过独立渠道确认审核人规则的指纹。创建规则、汇集签名和复查原证明的操作见 [多方审核确认书](docs/checkpoint-verification.md#多方审核确认书)。

## 验证审核规则历史

在**存证与回放**选择**审核规则历史**。导入 `results/review-policy-history/128/history.json.gz`，将同目录合成案例 `pins.json` 中的 `initial_policy_sha256` 和 `latest_revision_sha256` 填入相应输入框，点击**验证审核规则历史**。工作台应显示已核验至第 3 版，现行名单有 4 把公钥，门槛为 2 份签名。命令行还可按指定历史版本复核确认书，详见 [审核规则历史](docs/checkpoint-verification.md#审核规则历史)。

## 验证确认书签署所用的规则版本

在**存证与回放**选择**绑定规则版本的审核确认书**。从 `results/revision-bound-review/128/` 导入 `current-quorum.json.gz` 与 `history.json.gz`，分别填入该样本 `pins.json` 的初始和最新版本指纹。留空规则版本，点击**验证签署所用规则版本**，应显示 3 份签名绑定规则第 3 版。

换用同目录的 `historical-quorum.json.gz` 时，在版本栏输入 `1`，可复核第 1 版确认书。实验用第 1 版和第 3 版设置了相同名单和门槛，每份确认书仍只适用它所签的版本。签署、汇集与独立复查步骤见 [绑定规则版本的审核确认书](docs/checkpoint-verification.md#绑定规则版本的审核确认书)。

## 复核审核规则分歧

在**存证与回放**选择**审核规则分歧证据**，导入 `results/policy-divergence/divergence.json.gz`。从同目录 `short/pins.json` 取合成样本的 `initial_policy_sha256`，点击**验证审核规则分歧**。工作台应显示共同前序为第 2 版，分歧起于第 3 版。命令行可对照两条完整历史并导出证据，详见 [审核规则分歧证据](docs/checkpoint-verification.md#审核规则分歧证据)。

## 复核院校裁定书

在**存证与回放**选择**审核规则分歧裁定书**，导入 `results/policy-resolution/long/resolution.json.gz`，将同目录 `pins.json` 中的 `authority_sha256` 和 `decision_sha256` 填入相应字段。工作台应显示所选第 27 版的完整版本指纹，以及达到门槛的两份裁定签名。签发、汇集及关联确认书的操作见 [审核规则分歧裁定书](docs/checkpoint-verification.md#审核规则分歧裁定书)。

## 核验院校裁定发布历史

在**存证与回放**选择**院校裁定发布历史**。导入 `results/resolution-history/long/history.json.gz`，填入同目录 `pins.json` 中的 `authority_sha256` 和 `latest_publication_sha256`。工作台应显示已核验至第 27 次发布和当前裁定指纹。发布历史与裁定书分别保管。命令行可选择任一发布记录，复核配套裁定书及审核确认书。详见 [院校裁定发布历史](docs/checkpoint-verification.md#院校裁定发布历史)。

## 核验裁定权限交接

在同一核验页面导入 `results/resolution-handover/long/history.json.gz`，使用其 `pins.json` 中的 `initial_authority_sha256` 和 `latest_publication_sha256`。工作台会显示经核验的当前权限指纹及一次交接。样本在第 2 次发布时交接。历史复核可用 `--publication 1` 选择由原权限签发的裁定。详见 [院校裁定权限交接](docs/checkpoint-verification.md#院校裁定权限交接)。

## 用检查点核验指定裁定发布

在证据核验页选择「院校裁定发布证明」。上传 `results/resolution-checkpoint/long/head-witness.json.gz`，填入同目录 `pins.json` 的 `publication_checkpoint_sha256`，留空发布序号即可核验检查点末条（第 27 次发布）。换用 `archived-witness.json.gz` 时填写序号 1，可核验权限交接前的发布。院校实际复核时，检查点指纹须通过独立审计或可信渠道取得。通过命令行可进一步核验对应裁定书、联合确认书和原始证据。详见 [裁定发布检查点](docs/checkpoint-verification.md#裁定发布检查点)。

## 接续裁定发布检查点

`results/resolution-checkpoint-extension/long/` 提供第 1,023 次发布的末端证明和 8 条新增签名记录。用命令行 `resolution-history checkpoint-extend` 读取 `base-witness.json.gz` 和 `delta.json.gz`，演示指纹见同目录 `pins.json`。成功后可在工作台核验第 1,031 次发布的新末端证明。实际复核时请保留原来核准的检查点指纹，并独立确认下一次核验预期到达的末端发布指纹。详见 [接续裁定发布检查点](docs/checkpoint-verification.md#接续裁定发布检查点)。

## 更新历史裁定证明

使用 `resolution-history checkpoint-refresh` 可将已保存的历史发布证明更新到新检查点。演示文件在 `results/resolution-witness-refresh/long/`。在工作台选择「院校裁定发布证明」，上传 `refreshed-witness.json.gz`，填入该目录 `pins.json` 的 `advanced_checkpoint_sha256` 和发布序号 1。工作台会显示第 1 次发布时的权限指纹，以及新检查点覆盖的 1,031 次发布。详见 [更新历史裁定证明](docs/checkpoint-verification.md#更新历史裁定证明)。

## 核验批量裁定发布证明

在工作台选择「批量裁定发布证明」，上传 `results/resolution-batch/mixed/refreshed-batch.json.gz`。输入同目录 `pins.json` 的演示检查点指纹 `advanced_checkpoint_sha256`，并将 `expected_publications` 的序号用逗号或空格分隔输入。展开结果可查看各条发布时的裁定权限和正文指纹。正式复核时，预期序号和检查点指纹由复核方独立确认。批量导出、更新及单份裁定书复核可通过命令行执行。详见 [批量裁定发布证明](docs/checkpoint-verification.md#批量裁定发布证明)。

## 从批量证明提取指定发布

`checkpoint-select-batch` 可用原批量证明和同一可信检查点导出部分裁定的证明。演示文件在 `results/resolution-selection/mixed/`。用「批量裁定发布证明」核验 `subset.json.gz` 时，输入 `pins.json` 的 `advanced_checkpoint_sha256` 及 `selected_publications`。用「院校裁定发布证明」核验 `single.json.gz` 时，输入同一指纹和 `single_publication`。详见 [从批量证明提取指定发布](docs/checkpoint-verification.md#从批量证明提取指定发布)。

## 在同一检查点合并裁定证明

用 `checkpoint-merge-batch` 输入多份单条或批量证明、可信检查点和完整预期合并序号。演示位于 `results/resolution-merge/mixed/`。在工作台选择「批量裁定发布证明」，上传 `merged.json.gz`，输入 `pins.json` 的 `advanced_checkpoint_sha256` 及 `expected_publications`，即可核对合并结果。详见 [在同一检查点合并裁定证明](docs/checkpoint-verification.md#在同一检查点合并裁定证明)。

审核组持有基线和更新后两个检查点的证明时，用 `checkpoint-advance-merge-batch` 一次完成更新与合并。程序验证签名增量后计算新检查点，逐份验证证明，并复核最终序号。小型样例与可执行命令见 [合并检查点更新前后的裁定证明](docs/checkpoint-verification.md#合并检查点更新前后的裁定证明)。

签名增量中的裁定可通过 `--include-new-publication N` 直接导出证明。重复 `--publication N` 填写最终预期序号。只证明新增裁定时，提交基线末端证明和签名增量即可。新旧裁定一起交付时，同时提交持有的旧证明。详见 [从签名增量导出新增裁定证明](docs/checkpoint-verification.md#从签名增量导出新增裁定证明)。

跨越多次签名更新时，可用 `checkpoint-chain-merge-batch` 按时间顺序提交每段增量及其预期末端指纹，同时合并在各个检查点留存的证明。仍用 `--publication N` 指定最终预期序号，用 `--include-new-publication N` 从任意一段增量选取新增发布。详见 [合并多段增量中的裁定证明](docs/checkpoint-verification.md#合并多段增量中的裁定证明)。

从 v1.28.0 开始，命令行逐段读入并核验 JSON 或 gzip 增量。所有阶段和来源证明通过核验后，软件才写出合并结果。

## 复验独立持钥与轮换

    educreditlab custody demo --out ./custody-output

打开生成目录，查看 `custody-summary.json` 中的轮换顺序。也可直接使用压缩包内 `results/custody-demo/` 的样例。将其中两份 Proof JSON 分别导入工作台的**存证与回放**，填入该案例的信任指纹。两份回执应分别通过区块 #4 与 #7 的核验，均复算为 16 个学季学分。建立独立持钥试验网络的流程见 [机构持钥与计划性轮换](docs/managed-custody.md)。

查看 **results/benchmark_summary.json** 可核对本版本的实验结果。四份 CSV 分别记录历史规则、同学年政策追溯、分配优化和账本计时。运行下列命令可复验。

    educreditlab --workspace ./case-study demo --out ./demo-output
    educreditlab benchmark --out ./replication --repeats 30

两个学校的学分单位分别保留。数据仅涉及两份历史协议中的选定条目，可用来验证算法与回执行为。模拟成绩单、院校签名身份和后续政策情景均有明确标记。工作台与签名副本在本机运行。
