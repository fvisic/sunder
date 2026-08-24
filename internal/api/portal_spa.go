package api

// The portal SPA: one self-contained file, no external assets, no build
// step. Deliberately spartan - it is a rights surface, not a product UI.
//
// No inline event handlers: every listener is attached from the single
// nonce-carrying script block, so the CSP needs no 'unsafe-inline' and
// actually mitigates XSS. __NONCE__ is substituted per
// response by handlePortalSPA.
var portalSPA = []byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
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
     <button id="btn-start">Send me a login link</button></p>
  <p class="muted">We e-mail a one-time link (valid 15 minutes). Opening that link signs you in; you can also paste the code from it:</p>
  <p><input id="token" placeholder="login code"> <button id="btn-redeem">Sign in</button></p>
  <p id="loginmsg" class="muted"></p>
</div>

<div class="card" id="me" hidden>
  <p><button id="btn-logout">Sign out</button></p>
  <h2>Stored about you</h2>
  <div id="scopes"></div>
  <h2>Recent access history</h2>
  <pre id="trail"></pre>
  <h2>Erase everything</h2>
  <p class="muted">This removes your data from every internal system and cannot be undone. We e-mail a confirmation link first - signing in is not enough to erase.</p>
  <button class="danger" id="btn-erase">Request erasure</button>
  <p id="erasemsg" class="muted"></p>
  <p><input id="confirm" placeholder="erasure confirmation code">
     <button class="danger" id="btn-confirm">Confirm erasure</button></p>
</div>

<script nonce="__NONCE__">
"use strict";
const $ = (id) => document.getElementById(id);

async function api(path, body, method) {
  const res = await fetch("/portal/api/" + path, {
    method: method || (body ? "POST" : "GET"),
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (!res.ok) throw new Error(data.error || String(res.status));
  return data;
}

async function start() {
  try {
    const out = await api("start", { email: $("email").value });
    $("loginmsg").textContent = out.status;
  } catch (e) {
    $("loginmsg").textContent = e.message === "rate_limited"
      ? "Too many attempts - please wait a few minutes."
      : "Something went wrong. Please try again.";
  }
}

async function redeem(token) {
  try {
    await api("session", { token: (token || $("token").value).trim() });
    await load();
  } catch (e) {
    $("loginmsg").textContent = "That link is invalid or has expired.";
  }
}

async function load() {
  const me = await api("me");
  $("login").hidden = true;
  $("me").hidden = false;
  const host = $("scopes");
  host.textContent = "";
  for (const s of me.scopes || []) {
    const div = document.createElement("div");
    const h = document.createElement("h3");
    h.textContent = "System: " + s.scope;
    div.appendChild(h);
    const pre = document.createElement("pre");
    pre.textContent = JSON.stringify(s.attributes, null, 2);
    div.appendChild(pre);
    for (const c of s.consents || []) {
      const label = document.createElement("label");
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = c.granted;
      box.addEventListener("change", () => {
        api("consent", { cid: s.cid, purpose: c.purpose, granted: box.checked })
          .catch(() => { box.checked = !box.checked; });
      });
      label.appendChild(box);
      label.appendChild(document.createTextNode("allow: " + c.purpose));
      div.appendChild(label);
    }
    host.appendChild(div);
  }
  $("trail").textContent = (me.audit_trail || []).slice(-20)
    .map((e) => e.ts + "  " + e.client_id + "  " + e.action).join("\n") || "(empty)";
}

async function eraseRequest() {
  try {
    const out = await api("erase", {});
    $("erasemsg").textContent = out.status;
  } catch (e) {
    $("erasemsg").textContent = "Could not start erasure: " + e.message;
  }
}

async function eraseConfirm() {
  try {
    const out = await api("erase/confirm", { confirm_token: $("confirm").value.trim() });
    document.body.textContent = "";
    const h = document.createElement("h1");
    h.textContent = "Erased";
    const p = document.createElement("p");
    p.textContent = "Your data was removed from " + out.scopes +
      " system(s). Each one has been notified. This page will no longer work.";
    document.body.appendChild(h);
    document.body.appendChild(p);
  } catch (e) {
    $("erasemsg").textContent = "That confirmation code is invalid or has expired.";
  }
}

$("btn-start").addEventListener("click", start);
$("btn-redeem").addEventListener("click", () => redeem());
$("btn-erase").addEventListener("click", eraseRequest);
$("btn-confirm").addEventListener("click", eraseConfirm);
$("btn-logout").addEventListener("click", async () => {
  await api("logout", {});
  location.reload();
});

// The magic link IS a link: a token in the fragment (preferred - fragments
// are never sent to the server or logged in referrers) or the query string
// signs you in on open, and is scrubbed from the address bar immediately.
(function autoSignIn() {
  const fromHash = new URLSearchParams((location.hash || "").replace(/^#/, "")).get("token");
  const fromQuery = new URLSearchParams(location.search).get("token");
  const token = fromHash || fromQuery;
  if (!token) return;
  history.replaceState(null, "", location.pathname);
  redeem(token);
})();
</script>
</body>
</html>
`)
