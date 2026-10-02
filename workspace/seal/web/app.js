/* 设计签名封装看板（零依赖原生 JS）。
 * 数据全部来自 REST；点击信封可展开谱系、签名状态与完整校验结果。
 */
const api = (p, opt) => fetch(p, opt).then(async r => {
  const t = await r.text();
  let j;
  try { j = JSON.parse(t); } catch { j = t; }
  if (!r.ok) throw j;
  return j;
});
const esc = s => String(s ?? "").replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const short = x => x ? x.slice(0, 12) + "…" + x.slice(-6) : "";
const chip = (t, cls) => `<span class="chip"><span class="dot ${cls}"></span>${esc(t)}</span>`;
const stateChip = s => s === "PUBLISHED" ? chip("已发布", "bg-ok")
  : chip("已封装", "bg-warn");

async function loadAll() {
  await Promise.all([loadHealth(), loadEnvelopes(), loadAssemblies(),
    loadSigners(), loadAudit()]);
}
function showPane(name) {
  document.querySelectorAll(".tabs button").forEach(b =>
    b.classList.toggle("on", b.dataset.pane === name));
  document.querySelectorAll(".pane").forEach(p =>
    p.classList.toggle("on", p.id === "pane-" + name));
}

async function loadHealth() {
  try {
    const h = await api("/api/health");
    const ro = h.read_only
      ? `<span class="bad">只读降级</span>` : `<span class="ok">可写</span>`;
    document.getElementById("health").innerHTML =
      `${ro} · 服务密钥 <code>${esc(h.service_kid)}</code> · ` +
      `审计链 ${h.audit.ok ? `<span class="ok">完整(${h.audit.total})</span>`
        : `<span class="bad">断裂@${h.audit.broken_at}</span>`}` +
      (h.boot_issues.length
        ? ` · <span class="bad">${h.boot_issues.map(x => x.code).join(",")}</span>`
        : "");
  } catch (e) {
    document.getElementById("health").textContent = "服务不可用";
  }
}

async function loadEnvelopes() {
  const {envelopes} = await api("/api/envelopes");
  const box = document.getElementById("env-list");
  if (!envelopes.length) {
    box.innerHTML = `<div class="card muted">还没有信封。先在“组装”页创建组装并封装。</div>`;
    return;
  }
  box.innerHTML = "";
  for (const e of envelopes) {
    const div = document.createElement("div");
    div.className = "card";
    div.innerHTML = `
      <div class="row">
        <strong>${esc(e.release_name)}</strong>
        ${stateChip(e.state)}
        <span class="chip">${e.signature_count ?? "?"} 签名</span>
        <span class="chip mono">${short(e.envelope_id)}</span>
        <span class="muted">${esc(e.sealed_at)}</span>
        <span style="flex:1"></span>
        <button class="ghost" onclick="toggleEnv('${e.envelope_id}',this)">详情</button>
        <a class="ghost" style="text-decoration:none"
           href="/api/envelopes/${e.envelope_id}/bundle">离线包</a>
      </div>
      <div class="detail" style="display:none;margin-top:10px"></div>`;
    box.appendChild(div);
  }
}

async function toggleEnv(eid, btn) {
  const card = btn.closest(".card");
  const det = card.querySelector(".detail");
  if (det.style.display === "none") {
    det.style.display = "block";
    btn.textContent = "收起";
    await renderDetail(det, eid);
  } else {
    det.style.display = "none";
    btn.textContent = "详情";
  }
}

async function renderDetail(det, eid) {
  det.innerHTML = `<div class="muted">校验中…</div>`;
  const [env, verify, lineage] = await Promise.all([
    api(`/api/envelopes/${eid}`),
    api(`/api/envelopes/${eid}/verify`),
    api(`/api/envelopes/${eid}/lineage`)]);
  const sc = verify.signatures;
  const sigRows = sc.signatures.map(s => `
    <div class="sigline">
      ${s.valid ? '<span class="ok">✔ 有效</span>' : '<span class="bad">✗ 无效</span>'}
      <strong>${esc(s.signer_id)}</strong>
      <code>${esc(s.kid)}</code>
      <span class="muted">${esc(s.signed_at)}</span>
      ${s.current_status && s.current_status !== "ACTIVE"
        ? chip(`当前${s.current_status === "REVOKED" ? "已撤权" : "已轮换"}`,
               "bg-warn") : ""}
      ${!s.valid ? `<span class="bad">${esc((s.reasons||[]).join(","))}</span>` : ""}
    </div>`).join("") || `<div class="muted">尚无签名（未达发布条件）</div>`;
  const lineageHtml = lineage.ancestors.map((a, i) => `
    <div class="sigline">
      ${i === lineage.ancestors.length - 1 ? "▶" : "·"}
      <strong>${esc(a.release_name)}</strong>
      ${stateChip(a.state)}
      <code>${short(a.envelope_id)}</code>
      <span class="muted">${a.artifact_count} 制品 / ${a.signature_count} 签 / ${esc(a.sealed_at)}</span>
    </div>`).join("");
  const need = sc.required.length
    ? `<div class="muted">必需签名者：${sc.required.map(esc).join(", ")}
         ${sc.quorum_met ? `<span class="ok">（齐备）</span>`
           : `<span class="warn">（缺 ${sc.missing_signers.map(esc).join(",")}）</span>`}</div>`
    : "";
  det.innerHTML = `
    <div class="row">
      ${verify.ok ? chip("整体验真通过", "bg-ok") : chip("验真失败", "bg-bad")}
      ${sc.snapshot_ok ? chip("注册表快照有效", "bg-ok")
        : chip("注册表快照异常", "bg-bad")}
      ${sc.attestation_ok ? chip("发布作证有效", "bg-ok")
        : (sc.published ? chip("发布作证异常", "bg-bad") : chip("未发布·无作证", "bg-warn"))}
      <span class="muted">Merkle 根 <code>${short(verify.merkle_root)}</code></span>
      <span class="muted">制品核对 ${verify.artifacts_checked} 个</span>
    </div>
    ${verify.problems.length
      ? `<div class="problems bad">${verify.problems.map(p =>
          `<div>✗ ${esc(p.code)} ${p.name ? "· " + esc(p.name) : ""}
             ${p.reasons ? esc(p.reasons.join(",")) : ""}</div>`).join("")}</div>`
      : ""}
    <h4 style="margin:12px 0 4px">多方签名</h4>${sigRows}${need}
    <h4 style="margin:12px 0 4px">谱系（深度 ${lineage.depth}）</h4>
    <div>${lineageHtml}</div>
    <h4 style="margin:12px 0 4px">制品（${env.artifacts.length}）</h4>
    <table><thead><tr><th>类别</th><th>名称</th><th>大小</th><th>存储</th>
        <th>摘要</th><th>包含证明</th></tr></thead><tbody>
    ${env.artifacts.map(a => `
      <tr><td>${esc(a.kind)}</td><td>${esc(a.name)}</td>
        <td>${a.size}</td>
        <td>${a.storage === "chunked"
          ? `分块×${a.chunk_index.chunks.length}` : "内联"}</td>
        <td class="mono">${short(a.digest)}</td>
        <td><button class="ghost" onclick="showProof('${eid}','${esc(a.name)}',this)">
          证明</button></td></tr>`).join("")}
    </tbody></table>
    <div class="proofout"></div>`;
}

async function showProof(eid, name, btn) {
  const out = btn.closest(".card").querySelector(".proofout");
  const pr = await api(`/api/envelopes/${eid}/proof?name=${encodeURIComponent(name)}`);
  out.innerHTML = `<div class="card"><strong>${esc(name)}</strong>
    <div class="muted">叶摘要 <code>${short(pr.digest)}</code> → 根 <code>${short(pr.merkle_root)}</code></div>
    <pre>${esc(JSON.stringify(pr.proof, null, 2))}</pre></div>`;
}

async function loadAssemblies() {
  const {assemblies} = await api("/api/assemblies");
  const uploads = await Promise.all(
    assemblies.map(async a => {
      const r = await fetch(`/api/assemblies/${a.assembly_id}`);
      return r.json();
    }));
  const box = document.getElementById("asm-list");
  if (!assemblies.length) {
    box.innerHTML = `<div class="card muted">暂无组装。</div>`;
    return;
  }
  box.innerHTML = assemblies.map((a, i) => {
    const ups = uploads[i].uploads || [];
    const upHtml = ups.map(u => {
      const got = u.chunks.filter(c => c.received).length;
      const pct = Math.round(100 * got / u.total_chunks);
      return `<div class="sigline">
        <span class="mono">${short(u.session_id)}</span>
        ${esc(u.name)} · ${u.status} · ${got}/${u.total_chunks}
        <span class="bar"><i style="width:${pct}%"></i></span>${pct}%
      </div>`;
    }).join("");
    return `<div class="card">
      <div class="row">
        <strong>${esc(a.release_name)}</strong>
        ${chip(a.state, a.state === "SEALED" ? "bg-ok"
          : a.state === "OPEN" ? "bg-warn" : "bg-bad")}
        <span class="muted">${esc(a.assembly_id)} · by ${esc(a.created_by)}</span>
        ${a.envelope_id ? `<a class="ghost" style="text-decoration:none"
          href="/api/envelopes/${a.envelope_id}/verify" target="_blank">
          <code>${short(a.envelope_id)}</code></a>` : ""}
      </div>
      <div class="muted" style="margin-top:4px">
        制品 ${a.artifacts.length} · 必需签名 ${
          (a.required_signers||[]).join(",") || "（无）"}</div>
      ${upHtml ? `<div style="margin-top:6px">${upHtml}</div>` : ""}
    </div>`;
  }).join("");
}

async function loadSigners() {
  const {signers} = await api("/api/signers");
  document.getElementById("signer-list").innerHTML = signers.map(s => `
    <div class="card">
      <div class="row"><strong>${esc(s.signer_id)}</strong>
        ${chip(s.status, s.status === "ACTIVE" ? "bg-ok" : "bg-bad")}
        <span class="muted">${esc(s.name)} ${s.org ? "· " + esc(s.org) : ""}</span></div>
      <table style="margin-top:6px"><tbody>
      ${s.keys.map(k => `<tr>
        <td><code>${esc(k.kid)}</code></td>
        <td class="mono">${short(k.public_key)}</td>
        <td>${chip(k.status, k.status === "ACTIVE" ? "bg-ok"
          : k.status === "ROTATED" ? "bg-warn" : "bg-bad")}</td>
        <td class="muted">登记 ${esc(k.registered_at)}
          ${k.revoked_at ? "· 撤权 " + esc(k.revoked_at) : ""}
          ${k.rotated_at ? "· 轮换 " + esc(k.rotated_at) : ""}</td>
      </tr>`).join("")}
      </tbody></table>
    </div>`).join("") || `<div class="card muted">尚无签名者。</div>`;
}

async function loadAudit() {
  const {entries} = await api("/api/audit");
  const rows = [...entries].reverse().map(e => `
    <tr class="${e.result === "REJECT" ? "bad" : ""}">
      <td class="mono">${e.id}</td><td>${esc(e.ts)}</td>
      <td>${esc(e.actor)}</td><td>${esc(e.action)}</td>
      <td>${e.result === "OK"
        ? `<span class="ok">OK</span>` : `<span class="bad">${esc(e.result)}</span>`}</td>
      <td>${esc(e.reason || "")}</td>
      <td class="mono muted">${esc(JSON.stringify(e.detail))}</td>
    </tr>`).join("");
  document.getElementById("audit-list").innerHTML = `
    <table><thead><tr><th>#</th><th>时间</th><th>操作者</th><th>动作</th>
      <th>结果</th><th>原因码</th><th>详情</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

loadAll();
setInterval(() => {
  const on = document.querySelector(".tabs button.on").dataset.pane;
  if (on === "envelopes") loadEnvelopes();
  if (on === "assemblies") loadAssemblies();
}, 5000);
