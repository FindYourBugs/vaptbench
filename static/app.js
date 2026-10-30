// Workbench client: repeater, playbook loader, AI suggest, access matrix.
(function () {
  const root = document.querySelector("[data-tid]");
  if (!root) return;
  const tid = root.dataset.tid;
  const $ = (id) => document.getElementById(id);

  async function post(url, data) {
    const r = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    return r.json();
  }

  // --- Repeater ---
  const sendbtn = $("sendbtn");
  if (sendbtn) sendbtn.onclick = async () => {
    const res = $("resp");
    res.textContent = "sending...";
    const out = await post(`/target/${tid}/repeater`, {
      method: $("method").value, url: $("url").value,
      headers: $("headers").value, body: $("body").value,
      identity_id: $("identity").value || null,
    });
    if (out.blocked) { res.textContent = "⛔ SCOPE BLOCKED: " + out.reason; return; }
    if (!out.ok) { res.textContent = "error: " + out.reason; return; }
    res.textContent =
      `HTTP ${out.status}  ·  ${out.len} bytes  ·  session: ${out.identity}\n` +
      `----------------------------------------\n` + out.text;
  };

  // --- Playbook loader ---
  document.querySelectorAll(".pb-open").forEach((a) => {
    a.onclick = async (e) => {
      e.preventDefault();
      const panel = $("pbpanel");
      panel.textContent = "loading...";
      const pb = await (await fetch(`/playbook/${a.dataset.slug}`)).json();
      panel.textContent = pb.body || pb.error || "empty";
      panel.dataset.slug = a.dataset.slug;
    };
  });

  // --- AI suggest ---
  const aibtn = $("aibtn");
  if (aibtn) aibtn.onclick = async () => {
    const out = $("aiout");
    out.textContent = "thinking (local model)...";
    const r = await post(`/target/${tid}/ai-suggest`, {
      url: $("url").value,
      slug: $("pbpanel").dataset.slug || "",
      context: $("resp").textContent.slice(0, 2000),
    });
    out.textContent = r.answer || r.error || "no response";
  };

  // --- Automated login ---
  document.querySelectorAll(".login-one").forEach((b) => {
    b.onclick = async () => {
      const iid = b.dataset.iid;
      const s = $("lstat-" + iid);
      s.textContent = "logging in...";
      const r = await post(`/identity/${iid}/login`, {});
      s.textContent = (r.ok ? "ok: " : "fail: ") + r.message;
      s.className = "lstat " + (r.ok ? "good" : "bad");
    };
  });
  const loginall = $("loginall");
  if (loginall) loginall.onclick = async () => {
    loginall.textContent = "logging in all...";
    const r = await post(`/target/${tid}/login-all`, {});
    (r.results || []).forEach((row) => {
      // find matching role's status line
      document.querySelectorAll(".login-one").forEach((b) => {
        const s = $("lstat-" + b.dataset.iid);
      });
    });
    loginall.textContent = "Log in as all roles";
    // refresh to show captured statuses
    location.reload();
  };

  // --- Recon runners ---
  document.querySelectorAll(".tool-run").forEach((b) => {
    b.onclick = async () => {
      const out = $("recon-out");
      out.textContent = `running ${b.dataset.tool}... (may take a while)`;
      const r = await post(`/target/${tid}/recon`, { tool: b.dataset.tool });
      if (r.status === "blocked") { out.textContent = "⛔ SCOPE BLOCKED\n" + r.output; return; }
      let head = `[${r.status}] ${r.command}\n`;
      if (r.imported) head += `imported ${r.imported} URL(s) into Captured requests\n`;
      out.textContent = head + "----------------------------------------\n" + (r.output || "(no output)");
    };
  });

  // --- Access-control matrix ---
  document.querySelectorAll(".matrix-open").forEach((a) => {
    a.onclick = async (e) => {
      e.preventDefault();
      const box = $("matrix");
      box.textContent = "replaying across roles...";
      const m = await (await fetch(`/request/${a.dataset.rid}/matrix`)).json();
      let html = `<b>${m.request.method} ${m.request.url}</b><table><tr><th>role</th><th>status</th><th>len</th></tr>`;
      m.rows.forEach((row) => {
        html += `<tr><td>${row.role}</td><td>${row.blocked ? "⛔" : row.status}</td><td>${row.len || "-"}</td></tr>`;
      });
      html += "</table><small>Same status+length across roles that shouldn't all have access = possible IDOR/privesc.</small>";
      box.innerHTML = html;
    };
  });
})();
