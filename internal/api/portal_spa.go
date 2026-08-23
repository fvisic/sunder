package api

// The portal SPA: one self-contained file, no external assets, no build
// step. Deliberately spartan - it is a rights surface, not a product UI.
var portalSPA = []byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your data</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; color: #1a1a1a; background: #fafafa; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
  input, button { font: inherit; padding: .5rem .75rem; border-radius: 6px; border: 1px solid #bbb; }
  button { background: #1a1a1a; color: #fff; cursor: pointer; border: 0; }
  button.danger { background: #b3261e; }
  pre { background: #f0f0f0; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: .85rem; }
  .card { background: #fff; border: 1px solid #e5e5e5; border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }
  .muted { color: #666; font-size: .9rem; }
  label { display: flex; gap: .5rem; align-items: center; margin: .25rem 0; }
</style>
</head>
<body>
<h1>Your data, your rights</h1>
<p class="muted">See what is stored about you, manage consents, export, or erase. Powered by Sunder; this organization runs its own instance - no third party sees your data.</p>

<div class="card" id="login">
  <h2>Sign in</h2>
  <p><input id="email" type="email" placeholder="you@example.com" autocomplete="email">
     <button onclick="start()">Send me a login link</button></p>
  <p class="muted">We e-mail a one-time link (valid 15 minutes). If you received a link token, paste it:</p>
  <p><input id="token" placeholder="login token"> <button onclick="redeem()">Sign in</button></p>
  <p id="loginmsg" class="muted"></p>
</div>

<div class="card" id="me" hidden>
  <h2>Stored about you</h2>
  <div id="scopes"></div>
  <h2>Recent access history</h2>
  <pre id="trail"></pre>
  <h2>Erase everything</h2>
  <p class="muted">This removes your data from every internal system and cannot be undone.</p>
  <button class="danger" onclick="eraseStart()">Request erasure</button>
  <span id="erasestep"></span>
</div>

<script>
"use strict";
const $ = (id) => document.getElementById(id);
async function api(path, body, method) {
  const res = await fetch("/portal/api/" + path, {
    method: method || (body ? "POST" : "GET"),
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error((await res.json()).error || res.status);
  return res.json();
}
async function start() {
  const out = await api("start", { email: $("email").value });
  $("loginmsg").textContent = out.status;
}
async function redeem() {
  try {
    await api("session", { token: $("token").value.trim() });
    await load();
  } catch (e) { $("loginmsg").textContent = "That link is invalid or expired."; }
}
async function load() {
  const me = await api("me");
  $("login").hidden = true; $("me").hidden = false;
  $("scopes").innerHTML = "";
  for (const s of me.scopes || []) {
    const div = document.createElement("div");
    const h = document.createElement("h3"); h.textContent = "System: " + s.scope; div.appendChild(h);
    const pre = document.createElement("pre"); pre.textContent = JSON.stringify(s.attributes, null, 2); div.appendChild(pre);
    for (const c of s.consents || []) {
      const label = document.createElement("label");
      const box = document.createElement("input"); box.type = "checkbox"; box.checked = c.granted;
      box.onchange = () => api("consent", { cid: s.cid, purpose: c.purpose, granted: box.checked });
      label.appendChild(box); label.appendChild(document.createTextNode("allow: " + c.purpose));
      div.appendChild(label);
    }
    $("scopes").appendChild(div);
  }
  $("trail").textContent = (me.audit_trail || []).slice(-20)
    .map((e) => e.ts + "  " + e.client_id + "  " + e.action).join("\n") || "(empty)";
}
let confirmToken = "";
async function eraseStart() {
  if (!confirmToken) {
    const out = await api("erase", {});
    confirmToken = out.confirm_token;
    $("erasestep").innerHTML = "";
    const b = document.createElement("button"); b.className = "danger";
    b.textContent = "Yes, erase me everywhere - final"; b.onclick = eraseConfirm;
    $("erasestep").appendChild(b);
    return;
  }
}
async function eraseConfirm() {
  const out = await api("erase/confirm", { confirm_token: confirmToken });
  document.body.innerHTML = "<h1>Erased</h1><p>Your data was removed from " + out.scopes +
    " system(s). Each one has been notified. This page will no longer work.</p>";
}
</script>
</body>
</html>
`)
