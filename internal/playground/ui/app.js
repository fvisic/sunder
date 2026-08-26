// The playground SPA. Vanilla, no framework, no build step: it is served
// from the binary and has to keep working for as long as the API does.
//
// Every node is built with createElement + textContent. Nothing from the
// server is ever assigned to innerHTML - scenario notes and response bodies
// are data, and a demo that renders data as markup teaches injection.
"use strict";

const state = {
  tab: "walk",
  instance: "",
  scenarios: [],
  current: null,
  results: {},   // "<scenario>/<step>" -> result
  vars: {},
  busy: false,
  inbox: [],
  pollTimer: null,
};

const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const $ = (id) => document.getElementById(id);
const key = (scenario, step) => scenario + "/" + step;

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

async function load() {
  const data = await api("/api/scenarios");
  state.instance = data.instance;
  state.scenarios = data.scenarios;
  state.vars = data.vars || {};
  state.results = {};
  for (const r of data.results || []) state.results[key(r.scenario, r.step)] = r;
  state.current = state.scenarios[0] ? state.scenarios[0].id : null;
  $("instance").textContent = "against " + data.instance;
  $("identity").textContent = state.vars.demo_email || "";
  renderNav();
  renderStage();
}

function renderNav() {
  const nav = $("nav");
  nav.replaceChildren();
  for (const sc of state.scenarios) {
    const b = el("button", null, sc.title);
    b.type = "button";
    b.setAttribute("aria-current", String(sc.id === state.current));
    b.addEventListener("click", () => { state.current = sc.id; renderNav(); renderStage(); });
    nav.appendChild(b);
  }
}

function scenario() {
  return state.scenarios.find((s) => s.id === state.current);
}

function renderStage() {
  const stage = $("stage");
  stage.replaceChildren();
  const sc = scenario();
  if (!sc) {
    stage.appendChild(el("p", "muted", "No scenarios are loaded."));
    return;
  }

  const head = el("div", "card");
  head.appendChild(el("h1", null, sc.title));
  head.appendChild(el("p", "muted", sc.summary));

  const roles = el("div", "roles");
  for (const r of sc.roles) {
    const missing = (sc.missing_roles || []).includes(r.name);
    const chip = el("span", "chip" + (missing ? " warn" : ""),
      r.label + " - scope " + r.scope + (missing ? " (credential not configured)" : ""));
    roles.appendChild(chip);
  }
  head.appendChild(roles);

  const runAll = el("button", "primary", "Run every step");
  runAll.type = "button";
  runAll.disabled = state.busy || (sc.missing_roles || []).length > 0;
  runAll.addEventListener("click", () => runAll_(sc));
  const actions = el("div", "roles");
  actions.appendChild(runAll);
  head.appendChild(actions);

  if ((sc.missing_roles || []).length > 0) {
    head.appendChild(el("p", "err",
      "This walkthrough needs a credential for: " + sc.missing_roles.join(", ") +
      ". See examples/playground/README.md for the `sunder client create` commands."));
  }
  stage.appendChild(head);

  const panel = renderPanel(sc);
  if (panel) stage.appendChild(panel);
  ensureInboxPolling();

  sc.steps.forEach((step, i) => stage.appendChild(renderStep(sc, step, i)));
}

// renderPanel draws the scenario's specialized visualization above the step
// list. The panel is the point of the demo: the wire view teaches the API,
// the panel teaches what the API protects.
function renderPanel(sc) {
  switch (sc.panel) {
    case "handoff": return handoffPanel(sc);
    case "consent": return consentPanel(sc);
    case "webhook": return webhookPanel(sc);
    case "audit":   return auditPanel(sc);
    default:        return null;
  }
}

function handoffPanel(sc) {
  const card = el("div", "card");
  card.appendChild(el("h2", null, "Two systems, two pseudonyms"));
  const grid = el("div", "systems");
  const cols = [
    { label: sc.roles[0] ? sc.roles[0].label : "CRM", v: "crm_cid" },
    { label: sc.roles[1] ? sc.roles[1].label : "ERP", v: "erp_cid" },
  ];
  for (const c of cols) {
    const box = el("div", "system");
    box.appendChild(el("div", "muted", c.label));
    const value = state.vars[c.v];
    box.appendChild(el("div", "cid" + (value ? "" : " empty"), value || "no pseudonym yet"));
    grid.appendChild(box);
  }
  card.appendChild(grid);
  if (state.vars.crm_cid && state.vars.erp_cid) {
    const same = state.vars.crm_cid === state.vars.erp_cid;
    card.appendChild(el("p", "assert" + (same ? " fail" : ""), same
      ? "The two systems hold the SAME identifier - scope isolation is broken."
      : "Different identifiers for the same person: leaked CRM and ERP databases do not correlate."));
  }
  return card;
}

// resultsFor returns this scenario's executed steps, in step order.
function resultsFor(sc) {
  return sc.steps
    .map((step, i) => ({ step, i, res: state.results[key(sc.id, i)] }))
    .filter((r) => r.res);
}

// lastBody parses the response body of the last executed step whose path
// starts with prefix. The panels read the API's own answers rather than
// keeping a second copy of the state.
function lastBody(sc, method, prefix) {
  let found = null;
  for (const { step, res } of resultsFor(sc)) {
    if (step.method === method && step.path.startsWith(prefix) && res.response && res.response.body) {
      found = res.response.body;
    }
  }
  if (!found) return null;
  try { return JSON.parse(found); } catch (e) { return null; }
}

function consentPanel(sc) {
  const card = el("div", "card");
  card.appendChild(el("h2", null, "What the person has decided"));
  const granted = state.vars.consent_support;
  const row = el("div", "state");
  row.appendChild(el("span", "muted", "purpose \u201Csupport\u201D:"));
  if (granted === undefined) {
    row.appendChild(el("span", "badge", "no decision recorded"));
  } else {
    const yes = granted === "true";
    row.appendChild(el("span", "badge " + (yes ? "granted" : "withdrawn"), yes ? "granted" : "withdrawn"));
  }
  card.appendChild(row);
  card.appendChild(el("p", "muted",
    "Absence of a decision is not consent-governed; a withdrawal makes the vault refuse reads and " +
    "handoffs for that purpose, for every client, until it is re-granted."));
  const list = lastBody(sc, "GET", "/v1/consent/");
  if (list && Array.isArray(list.consents)) {
    for (const c of list.consents) {
      const line = el("div", "link");
      line.appendChild(el("span", "seq", c.purpose || "?"));
      line.appendChild(el("span", "badge " + (c.granted ? "granted" : "withdrawn"),
        c.granted ? "granted" : "withdrawn"));
      if (c.decided_at || c.ts) line.appendChild(el("span", "muted", c.decided_at || c.ts));
      card.appendChild(line);
    }
  }
  return card;
}

function webhookPanel(sc) {
  const card = el("div", "card");
  card.appendChild(el("h2", null, "Erasure webhook inbox"));
  card.appendChild(el("p", "muted",
    "This playground is registered as the crm scope's erasure webhook. Deliveries are signed with " +
    "HMAC-SHA256 over the exact body; the badge is the result of verifying that signature here, " +
    "not a claim from the sender."));
  if (!state.inbox.length) {
    card.appendChild(el("p", "muted", "Nothing delivered yet. Run the erasure step - delivery takes a second or two."));
  }
  for (const d of state.inbox) {
    const box = el("div", "delivery");
    const head = el("div", "delivery-head");
    head.appendChild(el("strong", null, d.event || "?"));
    head.appendChild(el("span", "chip", "scope " + (d.scope || "?")));
    head.appendChild(el("span", "chip", "erasure #" + (d.erasure_id || "?")));
    const cls = d.signature === "valid" ? "granted" : (d.signature === "invalid" ? "withdrawn" : "");
    head.appendChild(el("span", "badge " + cls, "signature " + d.signature));
    head.appendChild(el("span", "muted", d.received_at || ""));
    box.appendChild(head);
    if (d.body) box.appendChild(el("pre", null, d.body));
    card.appendChild(box);
  }
  return card;
}

function auditPanel(sc) {
  const card = el("div", "card");
  card.appendChild(el("h2", null, "Hash chain"));
  const verdict = lastBody(sc, "GET", "/v1/admin/audit/verify");
  if (!verdict) {
    card.appendChild(el("p", "muted", "Run the verification step to see the verdict and the chain."));
    return card;
  }
  // Three outcomes, not two: intact, a break at a named position, and
  // "not verifiable" (rows stranded outside the chain under sync sealing,
  // which has a reason but no position).
  let label = "chain intact";
  if (!verdict.ok) {
    label = verdict.broken_chain_seq
      ? "chain BROKEN at #" + verdict.broken_chain_seq
      : "chain NOT verifiable";
  }
  const row = el("div", "state");
  row.appendChild(el("span", "badge " + (verdict.ok ? "granted" : "withdrawn"), label));
  row.appendChild(el("span", "muted", (verdict.pending || 0) +
    " row(s) appended but not yet sealed" +
    (verdict.sealing ? " (" + verdict.sealing + " sealing)" : "")));
  card.appendChild(row);
  if (!verdict.ok && verdict.reason) card.appendChild(el("p", "assert fail", verdict.reason));

  const chain = lastBody(sc, "GET", "/v1/admin/audit/chain");
  if (chain && Array.isArray(chain.rows)) {
    const list = el("div", "chain");
    let prev = null;
    for (const r of chain.rows) {
      // A row whose prev_hash does not match the previous row's hash is
      // where a deletion or an insertion would show up.
      const linked = prev === null || r.prev_hash === prev;
      const line = el("div", "link" + (linked ? "" : " broken"));
      line.appendChild(el("span", "seq", "#" + r.chain_seq));
      line.appendChild(el("span", null, r.action));
      line.appendChild(el("span", "muted", r.client_id || "-"));
      line.appendChild(el("span", "hash", (r.hash || "").slice(0, 12) + "\u2026"));
      if (!linked) line.appendChild(el("span", "hash", "link mismatch"));
      list.appendChild(line);
      prev = r.hash;
    }
    card.appendChild(list);
  }
  return card;
}

// The webhook panel is the one view that changes without a click: the
// delivery arrives when the queue drains, seconds after the erasure step.
async function refreshInbox() {
  try {
    const out = await api("/api/inbox");
    state.inbox = out.deliveries || [];
  } catch (e) {
    state.inbox = [];
  }
}

function ensureInboxPolling() {
  const sc = scenario();
  const wants = sc && sc.panel === "webhook" && state.tab === "walk";
  if (wants && !state.pollTimer) {
    state.pollTimer = setInterval(async () => {
      const before = state.inbox.length;
      await refreshInbox();
      if (state.inbox.length !== before) renderStage();
    }, 2000);
  } else if (!wants && state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

function renderStep(sc, step, i) {
  const res = state.results[key(sc.id, i)];
  const card = el("div", "card step" + (res ? (res.ok ? " ok" : " fail") : ""));

  const head = el("div", "step-head");
  head.appendChild(el("span", "idx", "Step " + (i + 1)));
  head.appendChild(el("h2", null, step.label));
  head.appendChild(el("span", "actor", step.actor));
  head.appendChild(el("span", "chip", step.method + " " + step.path));
  head.appendChild(el("span", "chip", "expects " + step.expect));
  if (res && !res.error) {
    head.appendChild(el("span", "pill " + (res.ok ? "ok" : "fail"),
      "HTTP " + res.status + " in " + res.duration_ms + " ms"));
  }
  const run = el("button", "ghost", res ? "Run again" : "Run");
  run.type = "button";
  run.disabled = state.busy || (sc.missing_roles || []).includes(step.actor);
  run.addEventListener("click", () => runStep(sc, i));
  head.appendChild(run);
  card.appendChild(head);

  card.appendChild(el("p", "note", step.note));

  if (res) {
    if (res.error) card.appendChild(el("p", "err", res.error));
    if (res.request && res.request.method) {
      const wire = el("div", "wire");
      wire.appendChild(wirePane("Request", requestText(res.request)));
      wire.appendChild(wirePane("Response", responseText(res.response)));
      card.appendChild(wire);
    }
    for (const a of res.assertions || []) {
      card.appendChild(el("p", "assert" + (a.ok ? "" : " fail"),
        (a.ok ? "OK - " : "FAILED - ") + a.message));
    }
    if (res.captured && Object.keys(res.captured).length) {
      const vars = el("div", "vars");
      for (const [k, v] of Object.entries(res.captured)) {
        const line = el("span", "muted");
        line.appendChild(el("code", null, "{{" + k + "}}"));
        line.appendChild(document.createTextNode(" = " + v));
        vars.appendChild(line);
      }
      card.appendChild(vars);
    }
  }
  return card;
}

function wirePane(title, text) {
  const box = el("div");
  box.appendChild(el("h3", null, title));
  box.appendChild(el("pre", null, text));
  return box;
}

function requestText(req) {
  const lines = [req.method + " " + req.url];
  for (const [k, v] of Object.entries(req.headers || {})) lines.push(k + ": " + v);
  if (req.body) lines.push("", req.body);
  return lines.join("\n");
}

function responseText(res) {
  const lines = ["HTTP " + res.status];
  for (const [k, v] of Object.entries(res.headers || {})) if (v) lines.push(k + ": " + v);
  if (res.body) lines.push("", res.body);
  return lines.join("\n");
}

async function runStep(sc, i) {
  state.busy = true;
  renderStage();
  try {
    const out = await api("/api/run", { scenario: sc.id, step: i });
    state.results[key(sc.id, i)] = out.result;
    state.vars = out.vars || state.vars;
  } catch (e) {
    state.results[key(sc.id, i)] = {
      scenario: sc.id, step: i, ok: false, error: String(e.message || e),
      request: {}, response: {},
    };
  } finally {
    state.busy = false;
    renderStage();
  }
  if (sc.panel === "webhook") {
    await refreshInbox();
    renderStage();
  }
  return state.results[key(sc.id, i)];
}

// runAll_ stops at the first failed step: continuing past a failure would
// cascade "run the earlier steps first" errors and hide the real cause.
async function runAll_(sc) {
  for (let i = 0; i < sc.steps.length; i++) {
    const res = await runStep(sc, i);
    if (!res || !res.ok) break;
  }
}

function selectTab(tab) {
  state.tab = tab;
  $("tab-walk").setAttribute("aria-selected", String(tab === "walk"));
  $("tab-ref").setAttribute("aria-selected", String(tab === "ref"));
  $("stage").hidden = tab !== "walk";
  $("nav").hidden = tab !== "walk";
  $("reference").hidden = tab !== "ref";
  const frame = $("reference-frame");
  // Loaded on first use: the reference bundle is 800 KB, and most visitors
  // came for the walkthroughs.
  if (tab === "ref" && !frame.getAttribute("src")) frame.setAttribute("src", "/reference");
  // The two views have very different heights; keeping the old scroll
  // offset leaves the new one starting halfway down.
  window.scrollTo(0, 0);
  ensureInboxPolling();
}

$("tab-walk").addEventListener("click", () => selectTab("walk"));
$("tab-ref").addEventListener("click", () => selectTab("ref"));

$("btn-reset").addEventListener("click", async () => {
  const out = await api("/api/reset", {});
  state.vars = out.vars || {};
  state.results = {};
  state.inbox = [];
  $("identity").textContent = state.vars.demo_email || "";
  renderStage();
});

load().catch((e) => {
  $("stage").replaceChildren(el("p", "err", "Could not load the playground: " + e.message));
});
