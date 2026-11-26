"use strict";

const elt = (type, content, cls) => {
  const node = document.createElement(type);
  if (content !== undefined) node.textContent = content;
  if (cls) node.className = cls;
  return node;
};
const byId = id => document.getElementById(id);
const labels = {
  "uc-irvine": "加州大学尔湾分校",
  "uc-merced": "加州大学默塞德分校",
  "glendale-cc": "格伦代尔社区学院",
  "quarter units": "学季学分",
  "semester units": "学期学分"
};
const campusShort = {"uc-irvine": "尔湾", "uc-merced": "默塞德"};
const ruleStates = {
  recognized: ["条件满足", "ok"],
  requirements_unmet: ["条件未满足", "review"],
  allocation_conflict: ["分配受限", "review"]
};
const clauseStates = {
  eligible: "满足", no_completed_attempt: "截止日未完成",
  grade_below_minimum: "成绩低于要求", unranked_grade: "需要核查成绩类型"
};
let catalog;
let transcript;
let view = "compare";
let lastRun = 0;
let importRun = 0;
let ledgerRun = 0;

function label(value) { return labels[value] || value; }
function networkName(network) {
  if (network.key_management === "managed") return "机构持钥联盟链";
  return network.mode === "central" ? "中心化签名日志" : "本地联盟链";
}
function showStatus(message, error = false) {
  const node = byId("global-status");
  node.textContent = message;
  node.hidden = !message;
  node.classList.toggle("error", error);
}
async function api(url, body, headers = {}) {
  const encoded = body instanceof Blob || body instanceof FormData;
  const response = await fetch(url, body === undefined ? {} : {
    method: "POST",
    headers: body instanceof FormData ? headers : {"Content-Type": "application/json", ...headers},
    body: encoded ? body : JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "请求未完成");
  return result;
}
function option(value, text) {
  const node = elt("option", text);
  node.value = value;
  return node;
}
function policyName(policy, compact = false) {
  const kind = policy.kind === "synthetic" ? "合成政策" : "历史摘录";
  const campus = compact ? (campusShort[policy.receiver] || policy.receiver) : label(policy.receiver);
  return campus + " · " + policy.version + " · " + kind;
}
function showTranscript(newTranscript, description) {
  transcript = newTranscript;
  byId("case-description").textContent = description;
  const table = elt("table");
  const head = table.createTHead().insertRow();
  for (const text of ["源院校课程", "成绩", "完成日期"]) head.append(elt("th", text));
  const tbody = table.createTBody();
  for (const item of transcript.attempts) {
    const row = tbody.insertRow();
    for (const text of [item.course, item.grade, item.completed_on]) row.insertCell().textContent = text;
  }
  byId("transcript-preview").replaceChildren(table);
}
function showCase() {
  const entry = catalog.cases.find(c => c.id === byId("case-select").value);
  if (entry) showTranscript(entry.transcript, entry.description_zh);
}
function invalidateResults() {
  lastRun += 1;
  byId("solve-button").disabled = !byId("policy-0") && !(byId("before-height")?.value);
  byId("results").replaceChildren();
  showStatus("");
}
function appendTarget(parent, index, policies, selectedVersion) {
  const group = elt("fieldset");
  group.append(elt("legend", index === 0 ? "第一组" : "第二组"));
  const key = "policy-" + index;
  const title = elt("label", "院校与政策");
  title.htmlFor = key;
  const choices = elt("select");
  choices.id = key;
  for (const policy of policies) choices.append(option(policy.policy_sha256, policyName(policy, true)));
  const selected = policies.find(policy => selectedVersion(policy));
  if (selected) choices.value = selected.policy_sha256;
  const dateKey = "asof-" + index;
  const dateLabel = elt("label", "认定日期");
  dateLabel.htmlFor = dateKey;
  const when = elt("input");
  when.id = dateKey;
  when.type = "date";
  when.required = true;
  const update = () => {
    const p = catalog.policies.find(policy => policy.policy_sha256 === choices.value);
    const defaultDate = p.kind === "synthetic" ? "2023-07-15" : "2023-06-15";
    when.value = p.valid_from <= defaultDate && defaultDate < p.valid_until ? defaultDate : p.valid_from;
  };
  choices.addEventListener("change", update);
  choices.addEventListener("change", invalidateResults);
  when.addEventListener("change", invalidateResults);
  update();
  group.append(title, choices, dateLabel, when);
  parent.append(group);
}
function setupTargets() {
  const parent = byId("target-fields");
  parent.replaceChildren();
  const policies = catalog.policies.filter(p => p.issuer === transcript.issuer);
  byId("solve-button").disabled = policies.length === 0;
  if (!policies.length) {
    parent.append(elt("p", "当前成绩单的源院校暂无已登记规则。", "quiet"));
    return;
  }
  if (byId("compare-type").value === "timeline") {
    setupTimeline(parent, policies);
    return;
  }
  appendTarget(parent, 0, policies, p => p.receiver === "uc-irvine" && p.kind === "historical-extract");
  const temporal = byId("compare-type").value === "versions";
  appendTarget(parent, 1, policies, p => temporal
    ? p.receiver === "uc-irvine" && p.kind === "synthetic"
    : p.receiver === "uc-merced" && p.kind === "historical-extract");
}
function timelineControl(parent, id, title, tag) {
  const description = elt("label", title);
  description.htmlFor = id;
  const control = elt(tag);
  control.id = id;
  parent.append(description, control);
  return control;
}
function setupTimeline(parent, policies) {
  const scopes = new Map();
  for (const policy of policies) {
    const key = policy.receiver + "/" + policy.programme;
    if (!scopes.has(key)) scopes.set(key, []);
    scopes.get(key).push(policy);
  }
  const scope = timelineControl(parent, "timeline-scope", "接收院校与专业", "select");
  for (const [key, versions] of scopes) {
    scope.append(option(key, label(versions[0].receiver) + " · " + versions[0].programme));
  }
  const choose = timelineControl(parent, "timeline-date", "共同认定日期", "input");
  choose.type = "date";
  choose.required = true;
  const before = timelineControl(parent, "before-height", "较早登记视图", "select");
  const after = timelineControl(parent, "after-height", "较晚登记视图", "select");
  const chooseDates = () => {
    const preferred = catalog.demo_amendment?.date || "2023-06-15";
    const versions = scopes.get(scope.value);
    choose.value = versions.some(p => p.valid_from <= preferred && preferred < p.valid_until)
      ? preferred : versions[0].valid_from;
  };
  const update = () => {
    const versions = scopes.get(scope.value).filter(p => p.valid_from <= choose.value && choose.value < p.valid_until);
    const asOption = p => option(p.registered_height, p.version + " · #" + p.registered_height);
    before.replaceChildren(...versions.map(asOption));
    after.replaceChildren(option("", "最新已提交视图"), ...versions.map(asOption));
    invalidateResults();
  };
  scope.onchange = () => { chooseDates(); update(); };
  choose.onchange = update;
  before.onchange = after.onchange = invalidateResults;
  chooseDates();
  update();
  const demo = catalog.demo_amendment;
  if (demo && policies.some(p => p.policy_sha256 === demo.parent)
      && !policies.some(p => p.policy_sha256 === demo.revision)) {
    const loader = elt("button", "登记同学年修订示例", "secondary timeline-loader");
    loader.type = "button";
    loader.onclick = async () => {
      loader.disabled = true;
      try {
        const registered = await api("/api/demo-amendment", {});
        catalog = await api("/api/catalog");
        renderPolicies();
        setupTargets();
        showStatus("模拟修订已于区块 #" + registered.height + " 登记。可计算同日对照。");
      } catch (error) { showStatus(error.message, true); }
      finally { loader.disabled = false; }
    };
    parent.append(loader, elt("p", "示例将登记一条明确标注为模拟的修订规则。", "quiet"));
  }
}
function targets() {
  if (!byId("policy-0")) throw new Error("请先登记适用于源院校的政策。");
  return [0, 1].map(index => {
    const policy = catalog.policies.find(p => p.policy_sha256 === byId("policy-" + index).value);
    const when = byId("asof-" + index).value;
    if (when < policy.valid_from || when >= policy.valid_until) {
      throw new Error("请选择该政策版本适用的日期（" + policy.valid_from + " 至 " + policy.valid_until + " 之前）。");
    }
    return {receiver: policy.receiver, programme: policy.programme, as_of: when,
      known_height: policy.registered_height};
  });
}
function renderRule(rule) {
  const item = elt("details");
  const summary = elt("summary");
  const tag = ruleStates[rule.status];
  summary.append(elt("span", rule.label, "detail-title"), elt("br"), elt("span", tag[0], "badge " + tag[1]));
  item.append(summary);
  const info = elt("div", undefined, "rule-details");
  for (const route of rule.options) {
    const wording = route.id === rule.selected_option ? "已采用的课程组合" : "备选课程组合";
    info.append(elt("p", wording + " · " + route.id, "quiet"));
    const list = elt("ul");
    for (const clause of route.clauses) {
      let description = clause.course + " · 最低 " + clause.min_grade + " · " + clauseStates[clause.state];
      if (clause.attempt) description += "（" + clause.attempt.grade + "，" + clause.attempt.completed_on + "）";
      list.append(elt("li", description));
    }
    info.append(list);
  }
  for (const blocker of rule.allocation_blockers) {
    const reasons = [];
    if (blocker.competes_with.length) reasons.push("课程已分配给 " + blocker.competes_with.join("、"));
    if (blocker.total_cap) reasons.push("达到总学分上限");
    if (blocker.group_cap) reasons.push("达到分组学分上限");
    if (reasons.length) info.append(elt("p", reasons.join("；"), "quiet"));
  }
  info.append(elt("p", rule.evidence, "quiet"));
  item.append(info);
  return item;
}
function renderDecision(decision, input, selection, policyView, caption) {
  const section = elt("article", undefined, "card result-card");
  const top = elt("header", undefined, "result-top");
  top.append(elt("h3", caption || label(decision.receiver)));
  const note = decision.policy_kind === "synthetic" ? "合成政策" : "历史摘录";
  top.append(elt("p", note + " · " + decision.policy_version + " · " + decision.as_of, "quiet"));
  top.append(elt("p", "登记视图 #" + policyView.knowledge.height + " · 政策登记 #"
    + policyView.registration.height, "quiet"));
  const metric = elt("p", (decision.recognized_units / 100) + " ", "metric");
  metric.append(elt("small", label(decision.unit)));
  top.append(metric, elt("p", decision.recognized_rules + " / " + decision.rules.length + " 项规则满足", "quiet"));
  section.append(top);
  const body = elt("div", undefined, "result-body");
  for (const rule of decision.rules) body.append(renderRule(rule));
  if (catalog.network.key_management === "managed") {
    body.append(elt("p", "正式签发由接收院校使用独立密钥完成。", "quiet"));
    section.append(body);
    return section;
  }
  const actions = elt("div", undefined, "result-actions");
  const record = elt("button", "签发演示回执", "secondary");
  record.type = "button";
  record.onclick = async () => {
    record.disabled = true;
    try {
      const result = await api("/api/record", {transcript: input, target: selection});
      await setView("ledger");
      showStatus("回执位于第 " + result.height + " 个区块。");
    } catch (error) { showStatus(error.message, true); }
    finally { record.disabled = false; }
  };
  actions.append(record);
  body.append(actions);
  section.append(body);
  return section;
}
async function solveTimeline(input) {
  const [receiver, programme] = byId("timeline-scope").value.split("/");
  const target = {receiver, programme, as_of: byId("timeline-date").value};
  const after = byId("after-height").value;
  const result = await api("/api/compare-policy", {transcript: input, target,
    before_height: Number(byId("before-height").value), after_height: after ? Number(after) : null});
  const delta = result.delta.units;
  const wording = delta === null ? "按两个版本各自的学分单位列出结果。" :
    "较晚视图匹配学分变化 " + (delta > 0 ? "+" : "") + delta / 100 + " " + label(result.after.decision.unit);
  const description = [wording];
  if (result.delta.added_rules.length) description.push("新增 " + result.delta.added_rules.join("、"));
  if (result.delta.removed_rules.length) description.push("减少 " + result.delta.removed_rules.join("、"));
  return [
    elt("p", result.as_of + " · " + description.join(" · "), "timeline-result"),
    ...[result.before, result.after].map((item, index) => renderDecision(
      item.decision, input, {...target, known_height: item.policy_view.knowledge.height},
      item.policy_view, index ? "较晚登记视图" : "较早登记视图"))
  ];
}
async function solve() {
  const turn = ++lastRun;
  const trigger = byId("solve-button");
  trigger.disabled = true;
  showStatus("");
  try {
    const input = transcript;
    let cards;
    if (byId("compare-type").value === "timeline") cards = await solveTimeline(input);
    else {
      const selected = targets();
      const result = await api("/api/preview", {transcript: input, targets: selected});
      cards = result.results.map((d, i) => renderDecision(d, input, selected[i], result.views[i]));
    }
    if (turn === lastRun) byId("results").replaceChildren(...cards);
  } catch (error) {
    if (turn === lastRun) showStatus(error.message, true);
  } finally {
    if (turn === lastRun) trigger.disabled = false;
  }
}
function renderPolicies() {
  const parent = byId("policy-items");
  const cards = catalog.policies.map(p => {
    const article = elt("article", undefined, "card policy-item");
    article.append(elt("h2", policyName(p)), elt("p", p.valid_from + " ≤ 日期 < " + p.valid_until, "meta"),
                   elt("p", p.provenance.note), elt("p", p.policy_sha256, "hash"));
    const timeLabel = p.time_basis === "finalization" ? "提交时间" : "提案时间";
    article.append(elt("p", "登记区块 #" + p.registered_height + " · " + timeLabel + " " + p.registered_at, "quiet"));
    if (p.supersedes) {
      const parent = catalog.policies.find(q => q.policy_sha256 === p.supersedes);
      article.append(elt("p", "修订父版本 " + (parent?.version || p.supersedes) + " · " + p.revision_reason, "quiet"));
    }
    if (p.provenance.url) {
      const a = elt("a", p.provenance.title);
      a.href = p.provenance.url;
      a.rel = "noopener noreferrer";
      a.target = "_blank";
      article.append(a);
    }
    if (p.cap !== null) article.append(elt("p", "总上限 · " + (p.cap / 100) + " " + label(p.unit)));
    for (const link of p.reuse) article.append(elt("p", "允许重复使用 · " + link.course
      + " → " + link.rules.join(" / "), "quiet"));
    for (const rule of p.rules) {
      const detail = elt("details");
      detail.append(elt("summary", rule.label + " · " + (rule.units / 100) + " " + label(p.unit)));
      for (const alternative of rule.options) detail.append(elt("p", alternative.all_of
        .map(x => x.course + " ≥ " + x.min_grade).join(" + ")));
      article.append(detail);
    }
    return article;
  });
  parent.replaceChildren(...cards);
}
function replayBanner(result) {
  if (result.publication_checkpoint_batch_verified) {
    const publications = byId("batch-publications");
    for (const item of result.verified_publications) {
      const row = elt("li", "第 " + item.verified_publication + " 次发布");
      row.append(elt("p", "裁定权限指纹 " + item.verified_authority_sha256, "hash"),
                 elt("p", "裁定正文指纹 " + item.verified_decision_sha256, "hash"));
      publications.append(row);
    }
    byId("publication-batch-results").hidden = false;
    showStatus("已核验 " + result.verified_publications.length + " 条指定发布，检查点覆盖 "
      + result.publication_count + " 次发布。");
    return;
  }
  if (result.publication_checkpoint_verified) {
    const position = result.is_checkpoint_head ? "该条为检查点末条。" : "该条为历史发布。";
    showStatus("检查点覆盖 " + result.publication_count + " 次发布，已核验第 "
      + result.verified_publication + " 次发布。" + position + "当时的裁定权限指纹 "
      + result.verified_authority_sha256 + "，裁定正文指纹 " + result.verified_decision_sha256 + "。");
    return;
  }
  if (result.resolution_history_verified) {
    const count = result.publication_count;
    const handover = result.active_authority_sha256
      ? "已核验 " + result.authority_handover_count + " 次权限交接。当前权限指纹 " + result.active_authority_sha256 + "。"
      : "";
    showStatus(count ? "裁定发布历史已核验至第 " + count + " 次发布。当前裁定指纹 "
      + result.current_decision_sha256 + "。" + handover : "裁定发布历史已核验，尚未发布裁定。");
    return;
  }
  if (result.policy_resolution_verified) {
    showStatus("裁定书已核验。采用审核规则第 " + result.selected_revision + " 版，有效裁定签名 "
      + result.resolution_signer_count + " 份，需达到 " + result.resolution_threshold
      + " 份。所选版本指纹 " + result.selected_revision_sha256 + "。");
    return;
  }
  if (result.policy_divergence_verified) {
    showStatus("分歧证据已核验。两条历史在第 " + result.divergent_revision + " 版分歧，此前共用第 "
      + result.shared_revision + " 版。共同前序规则中有 " + result.shared_predecessor_approvers.length
      + " 把公钥签署了两项变更。");
    return;
  }
  if (result.policy_history_verified) {
    showStatus("审核规则历史已核验。已验证至第 " + result.latest_revision + " 版，含 "
      + result.reviewer_count + " 把审核公钥，至少需要 " + result.threshold + " 份有效签名。");
    return;
  }
  if (result.quorum_verified) {
    const heading = result.revision_binding_verified
      ? "多方签名已绑定审核规则第 " + result.policy_revision + " 版。"
      : "多方审核确认书已核验。";
    showStatus(heading + "有效签名 " + result.signer_count + " 份，需达到 "
      + result.threshold + " 份。签署记录注明 " + result.replay_count + " 份复算、"
      + result.anchor_count + " 份存证核验。检查点 #" + result.checkpoint_height + "。");
    return;
  }
  if (result.review_attestation) {
    showStatus("审核确认书签名已核验。签署记录注明 " + result.replay_count + " 份复算、"
      + result.anchor_count + " 份存证核验。检查点 #" + result.checkpoint_height + "。");
    return;
  }
  const checkpoint = result.checkpoint_height === undefined ? "" : " 已核验检查点 #" + result.checkpoint_height + "。";
  if (result.batch) {
    const entries = document.createDocumentFragment();
    for (const receipt of result.receipts) {
      const item = elt("li");
      const decision = receipt.decision;
      const labelText = decision
        ? " · " + decision.receiver + " · " + decision.policy_version + " · "
          + (decision.recognized_units / 100) + " " + label(decision.unit)
        : " · 存证已核验";
      item.append(elt("p", "区块 #" + receipt.height + labelText),
        elt("p", receipt.receipt_sha256, "hash"));
      entries.append(item);
    }
    byId("batch-receipts").replaceChildren(entries);
    byId("batch-results").hidden = false;
    if (result.review_plan_sha256) {
      showStatus("审核计划核验通过。已复算 " + result.replay_count + " 份，仅核验存证 "
        + result.anchor_count + " 份。" + checkpoint);
    } else {
      showStatus((result.replayed ? "批量复算通过" : "批量存证通过")
        + "。已核验 " + result.receipt_count + " 份回执。" + checkpoint);
    }
    return;
  }
  if (result.anchor_verified) {
    showStatus("存证核验通过。已确认第 " + result.height + " 个区块中的回执摘要。" + checkpoint);
    return;
  }
  const knowledge = result.policy_view?.knowledge;
  const replica = result.replica === "coordinator" ? "。从本地档案复算"
    : result.replica ? "。核验副本 " + result.replica : "";
  showStatus("通过核验。第 " + result.height + " 个区块，按 " + result.decision.policy_version
    + " 回放，确认 " + result.decision.recognized_rules + " 项规则和 "
    + (result.decision.recognized_units / 100) + " " + label(result.decision.unit)
    + (knowledge ? "。原登记视图 #" + knowledge.height : "") + replica + "。" + checkpoint);
}
async function renderLedger(cursor = null, previousPages = []) {
  const round = ++ledgerRun;
  const query = cursor ? "?" + new URLSearchParams(cursor) : "";
  const data = await api("/api/history" + query);
  if (round !== ledgerRun || view !== "ledger") return;
  const n = data.network;
  const mode = networkName(n);
  byId("network-label").textContent = mode + " · 区块 " + n.height;
  const summary = byId("ledger-summary");
  const states = {current: "已同步", behind: "待同步", advancing: "更新中",
    empty: "无区块", inconsistent: "历史不一致", invalid: "校验失败", external: "由节点维护"};
  summary.replaceChildren(elt("h2", mode), elt("p", "已提交 " + n.height + " 个区块 · 签名门槛 " + n.quorum),
    elt("p", "副本状态 · " + Object.entries(n.replica_status).map(([name, info]) =>
      name + " " + states[info.state] + (info.height === null ? "" : " #" + info.height)).join(" / "), "quiet"),
    elt("p", "信任清单 SHA-256 · " + n.manifest_sha256, "hash"));
  if (n.pending_height !== null) summary.append(elt("p", "待提交区块 #" + n.pending_height, "quiet"));
  if (n.key_management === "managed") {
    const keys = elt("details");
    keys.append(elt("summary", "当前公钥 · 已登记 " + n.rotation_count + " 次轮换"));
    for (const [group, members] of Object.entries(n.active_public_keys)) {
      for (const [identity, key] of Object.entries(members)) {
        keys.append(elt("p", (group === "actors" ? "院校" : "验证节点")
          + " · " + label(identity) + " · " + key, "hash"));
      }
    }
    summary.append(keys);
  }
  const entries = [];
  for (const b of data.blocks) {
    const row = elt("div", undefined, "entry");
    const info = elt("div");
    const name = {"policy": "登记政策", "policy-revision": "登记修订",
      "receipt": "签发回执", "key-rotation": "密钥轮换"}[b.kind];
    info.append(elt("strong", "#" + b.height + " · " + label(b.actor) + " · " + name));
    const policy = b.kind === "policy-revision" ? b.payload.policy : b.payload;
    const details = b.kind === "receipt" ? b.payload.receipt_sha256
      : b.kind === "key-rotation" ? "新公钥 · " + b.payload.replacement_key : policy.version + " · " + policy.policy_sha256;
    info.append(elt("p", details, "hash"));
    if (b.kind === "key-rotation") {
      const role = b.payload.role === "actor" ? "院校" : "验证节点";
      info.append(elt("p", role + " · 新公钥自区块 #" + (b.height + 1) + " 起使用", "quiet"));
      info.append(elt("p", b.payload.reason, "quiet"));
    }
    if (b.kind === "receipt" && b.payload.knowledge) {
      info.append(elt("p", "签发采用登记视图 #" + b.payload.knowledge.height, "quiet"));
    }
    info.append(elt("p", b.votes.length + " 个签名 · "
      + (b.time_basis === "finalization" ? "提交 " : "提案 ")
      + new Date(b.recorded_at).toLocaleString(), "quiet"));
    row.append(info);
    if (b.kind === "receipt") {
      const actions = elt("div", undefined, "entry-actions");
      const replay = elt("button", "回放", "secondary");
      replay.type = "button";
      replay.onclick = async () => {
        replay.disabled = true;
        try { replayBanner(await api("/api/replay", {receipt: b.payload.receipt_sha256})); }
        catch (error) { showStatus(error.message, true); }
        finally { replay.disabled = false; }
      };
      const download = elt("a", "完整回执（含成绩）", "secondary");
      download.href = "/api/bundle?receipt=" + encodeURIComponent(b.payload.receipt_sha256);
      download.download = "educreditlab-review-bundle.json";
      const anchor = elt("a", "仅存证证明", "secondary");
      anchor.href = download.href + "&mode=anchor";
      anchor.download = "educreditlab-anchor.json";
      const packed = elt("a", "压缩回执（含成绩）", "secondary");
      packed.href = download.href + "&encoding=gzip";
      packed.download = "educreditlab-review-bundle.json.gz";
      actions.append(replay, download, anchor, packed);
      row.append(actions);
    }
    entries.push(row);
  }
  byId("ledger-items").replaceChildren(...entries);
  const page = data.page;
  const pin = {snapshot_height: page.snapshot_height, snapshot_sha256: page.snapshot_sha256};
  const here = cursor || {...pin, before_height: page.snapshot_height + 1};
  const first = data.blocks[0]?.height;
  const last = data.blocks.at(-1)?.height;
  const info = first === undefined ? "暂无已提交记录。"
    : "固定账本视图 #" + page.snapshot_height + " · 显示 #" + first + " 至 #" + last;
  const controls = byId("history-controls");
  controls.replaceChildren(elt("p", info, "quiet"));
  const control = (label, action, disabled = false) => {
    const button = elt("button", label, "secondary");
    button.type = "button";
    button.disabled = disabled;
    button.onclick = () => action().catch(error => showStatus(error.message, true));
    controls.append(button);
  };
  control("刷新到最新", () => renderLedger());
  control("上一页", () => renderLedger(previousPages.at(-1), previousPages.slice(0, -1)), !previousPages.length);
  control("更早记录", () => renderLedger({...pin, before_height: page.next_before}, [...previousPages, here]),
    page.next_before === null);
}
async function setView(next) {
  view = next;
  for (const key of ["compare", "policies", "ledger"]) byId(key).hidden = key !== view;
  for (const button of document.querySelectorAll("[data-view]")) {
    const selected = button.dataset.view === view;
    button.classList.toggle("active", selected);
    if (selected) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  showStatus("");
  if (view === "ledger") await renderLedger();
  if (view === "policies") {
    const count = catalog.policies.length;
    catalog = await api("/api/catalog");
    renderPolicies();
    if (catalog.policies.length !== count) {
      setupTargets();
      invalidateResults();
    }
  }
}
function selectedFile(input, maxSize, expected = "JSON") {
  const file = input.files[0];
  if (!file) throw new Error("请选择 " + expected + " 文件。");
  if (file.size > maxSize * 1024 * 1024) throw new Error("文件大小需在 " + maxSize + " MiB 以内。");
  return file;
}
async function init() {
  try {
    catalog = await api("/api/catalog");
    byId("network-label").textContent = networkName(catalog.network) + " · 区块 " + catalog.network.height;
    const select = byId("case-select");
    select.replaceChildren(...catalog.cases.map(c => option(c.id, c.label_zh)));
    renderPolicies();
    showCase();
    setupTargets();
    if (byId("policy-0")) await solve();
  } catch (error) { showStatus(error.message, true); }
}
for (const button of document.querySelectorAll("[data-view]")) {
  button.onclick = () => setView(button.dataset.view).catch(error => showStatus(error.message, true));
}
byId("compare-form").onsubmit = event => { event.preventDefault(); solve(); };
byId("compare-type").onchange = () => { if (catalog) { setupTargets(); invalidateResults(); } };
byId("case-select").onchange = () => {
  importRun += 1;
  showCase();
  setupTargets();
  invalidateResults();
};
byId("transcript-file").onchange = async event => {
  const turn = ++importRun;
  try {
    const response = await api("/api/transcript", selectedFile(event.target, 2));
    if (turn !== importRun) return;
    showTranscript(response.transcript, "本地导入");
    byId("case-select").selectedIndex = -1;
    setupTargets();
    invalidateResults();
    showStatus("成绩单已导入。请选择政策并计算。");
  } catch (error) { if (turn === importRun) showStatus(error.message, true); }
};
function clearBatchResults() {
  byId("batch-results").hidden = true;
  byId("batch-results").open = false;
  byId("batch-receipts").replaceChildren();
  byId("publication-batch-results").hidden = true;
  byId("publication-batch-results").open = false;
  byId("batch-publications").replaceChildren();
}
const verifyMode = byId("verify-mode");
const verifyLabels = {proof: "验证并回放", attestation: "验证审核确认书", quorum: "验证多方审核确认书",
  history: "验证审核规则历史", revision: "验证签署所用规则版本", divergence: "验证审核规则分歧",
  resolution: "验证审核规则裁定书", publication: "验证裁定发布历史", "publication-witness": "验证发布证明",
  "publication-batch": "验证批量发布证明"};
verifyMode.onchange = () => {
  for (const kind of Object.keys(verifyLabels)) {
    const fields = byId(kind + "-verification-fields");
    fields.hidden = fields.disabled = verifyMode.value !== kind;
  }
  byId("verifier").querySelector("button[type=submit]").textContent = verifyLabels[verifyMode.value];
  byId("proof-file-label").textContent = verifyMode.value === "revision" ? "多方审核确认书" : "选择文件";
  clearBatchResults();
  showStatus("");
};
byId("verifier").onsubmit = async event => {
  event.preventDefault();
  clearBatchResults();
  const submit = byId("verifier").querySelector("button[type=submit]");
  submit.disabled = true;
  verifyMode.disabled = true;
  try {
    const file = selectedFile(byId("proof-file"), 16, "JSON 或 gzip");
    const media = file.name.toLowerCase().endsWith(".gz") ? "application/gzip" : "application/json";
    if (verifyMode.value === "revision") {
      const history = selectedFile(byId("revision-history-file"), 16, "JSON 或 gzip");
      const files = new FormData();
      files.append("history", history);
      files.append("bundle", file);
      const headers = {
        "X-EduCredit-Initial-Policy": byId("revision-initial-fingerprint").value.trim(),
        "X-EduCredit-Revision": byId("revision-latest-fingerprint").value.trim()
      };
      const revision = byId("selected-review-revision").value.trim();
      if (revision) headers["X-EduCredit-Review-Revision"] = revision;
      showStatus("正在核验签署所用规则版本。");
      replayBanner(await api("/api/verify-revision-review", files, headers));
      return;
    }
    if (verifyMode.value === "history") {
      showStatus("正在核验审核规则历史。");
      replayBanner(await api("/api/verify-policy-history", file, {
        "Content-Type": media,
        "X-EduCredit-Initial-Policy": byId("history-initial-fingerprint").value.trim(),
        "X-EduCredit-Revision": byId("history-revision-fingerprint").value.trim()
      }));
      return;
    }
    if (verifyMode.value === "divergence") {
      showStatus("正在核验审核规则分歧。");
      replayBanner(await api("/api/verify-policy-divergence", file, {
        "Content-Type": media,
        "X-EduCredit-Initial-Policy": byId("divergence-initial-fingerprint").value.trim()
      }));
      return;
    }
    if (verifyMode.value === "resolution") {
      showStatus("正在核验院校裁定书。");
      replayBanner(await api("/api/verify-policy-resolution", file, {
        "Content-Type": media,
        "X-EduCredit-Authority": byId("resolution-authority-fingerprint").value.trim(),
        "X-EduCredit-Decision": byId("resolution-decision-fingerprint").value.trim()
      }));
      return;
    }
    if (verifyMode.value === "publication") {
      showStatus("正在核验裁定发布历史。");
      replayBanner(await api("/api/verify-resolution-history", file, {
        "Content-Type": media,
        "X-EduCredit-Authority": byId("publication-authority-fingerprint").value.trim(),
        "X-EduCredit-Publication": byId("publication-tip-fingerprint").value.trim()
      }));
      return;
    }
    if (verifyMode.value === "publication-witness") {
      const headers = {"Content-Type": media,
        "X-EduCredit-Publication-Checkpoint": byId("publication-checkpoint-fingerprint").value.trim()};
      const number = byId("selected-publication").value.trim();
      if (number) headers["X-EduCredit-Publication-Number"] = number;
      showStatus("正在核验院校裁定发布证明。");
      replayBanner(await api("/api/verify-resolution-checkpoint", file, headers));
      return;
    }
    if (verifyMode.value === "publication-batch") {
      const numbers = byId("selected-publications").value.trim().split(/[\s,，]+/).join(",");
      showStatus("正在核验批量裁定发布证明。");
      replayBanner(await api("/api/verify-resolution-checkpoint-batch", file, {
        "Content-Type": media,
        "X-EduCredit-Publication-Checkpoint": byId("publication-batch-fingerprint").value.trim(),
        "X-EduCredit-Publication-Numbers": numbers
      }));
      return;
    }
    if (verifyMode.value === "quorum") {
      showStatus("正在核验多方审核确认书。");
      replayBanner(await api("/api/verify-quorum", file, {
        "Content-Type": media,
        "X-EduCredit-Policy": byId("quorum-policy-fingerprint").value.trim()
      }));
      return;
    }
    if (verifyMode.value === "attestation") {
      showStatus("正在核验审核确认书签名。");
      replayBanner(await api("/api/verify-attestation", file, {
        "Content-Type": media,
        "X-EduCredit-Reviewer": byId("reviewer-fingerprint").value.trim(),
        "X-EduCredit-Plan": byId("attested-plan-fingerprint").value.trim()
      }));
      return;
    }
    showStatus("正在验证签名和历史记录。");
    const headers = {"Content-Type": media, "X-EduCredit-Trust": byId("fingerprint").value.trim()};
    const checkpoint = byId("checkpoint-fingerprint").value.trim();
    if (checkpoint) headers["X-EduCredit-Checkpoint"] = checkpoint;
    const plan = byId("plan-fingerprint").value.trim();
    if (plan) headers["X-EduCredit-Plan"] = plan;
    replayBanner(await api("/api/verify-file", file, headers));
  } catch (error) { showStatus(error.message, true); }
  finally {
    submit.disabled = false;
    verifyMode.disabled = false;
  }
};
init();

