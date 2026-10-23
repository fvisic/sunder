#!/usr/bin/env bash
# Every feature must land in every artifact that describes it.
#
# v0.5.0 shipped with the Helm chart missing five config variables, the
# Postman collection covering 14 of ~40 routes while the documentation
# claimed otherwise, and docs-site missing 20 variables docs/CONFIG.md had.
# Each gap was found by a person asking. The two guards that already existed
# - ops/check-config-docs.sh and TestEveryRouteIsDocumented - have never let
# one through, so this extends the same shape to the remaining artifacts.
#
# Four checks, each independent, all reported before the script exits:
#
#   helm      a SUNDER_* in the config reference must be settable via the chart
#   postman   a documented route must have a request in the collection
#   sdk       a route wrapped by SOME SDKs must be wrapped by all six
#   mirror    docs/CONFIG.md and the docs-site page must not disagree
#
# Deliberate omissions live in the allow-lists at the top of each check, next
# to the reason. An omission is a decision someone wrote down, not a gap.
set -uo pipefail

cd "$(dirname "$0")/.."
fail=0

section() { printf '\n== %s\n' "$1"; }
bad() { echo "::error::$1"; fail=1; }

# ---------------------------------------------------------------- helm ------
section "helm: every documented variable is settable through the chart"
python3 - <<'PY' || fail=1
import re, subprocess, sys

# Variables a chart cannot or should not expose, with the reason.
EXEMPT = {
    # Set by the chart itself from structured values, not passed through.
    "SUNDER_DB_URL": "rendered from database.existingSecret",
    "SUNDER_LISTEN": "the chart owns the container port",
    "SUNDER_TLS_CERT": "rendered from the tls secret mount",
    "SUNDER_TLS_KEY": "rendered from the tls secret mount",
    "SUNDER_MTLS_CA": "rendered from the mtls secret mount",
    "SUNDER_SIGNER_SOCKET": "rendered when signer.enabled",
    "SUNDER_KEYSTORE": "derived from keystore.type",
    "SUNDER_VAULT_ADDR": "rendered from keystore.vault",
    "SUNDER_VAULT_TOKEN": "rendered from keystore.vault.existingSecret",
    "SUNDER_VAULT_MOUNT": "rendered from keystore.vault",
    "SUNDER_METRICS_TOKEN": "rendered from metrics.existingSecret",
    "SUNDER_REDIS_ADDR": "rendered from redis.addr",
    "SUNDER_REDIS_PASSWORD": "rendered from redis.existingSecret",
    "SUNDER_REDIS_FAIL_CLOSED": "rendered from redis.failClosed",
    "SUNDER_AUDIT_SEAL_EXTERNAL": "rendered from audit.sealer.enabled",
    "SUNDER_PORTAL_ENABLED": "rendered from portal.enabled",
    "SUNDER_PORTAL_LISTEN": "rendered from portal.listenPort",
    "SUNDER_PORTAL_BASE_URL": "rendered from portal.baseUrl",
    "SUNDER_PORTAL_COOKIE_INSECURE": "rendered from portal.cookieInsecure",
    "SUNDER_PORTAL_CLIENT_IP_HEADER": "rendered from portal.clientIpHeader",
    "SUNDER_PORTAL_TRUSTED_PROXY_HOPS": "rendered from portal.trustedProxyHops",
    "SUNDER_TSA_URL": "rendered from anchor.tsaUrl",
    "SUNDER_TSA_CACERT": "rendered from anchor.caSecretName",
    "SUNDER_ANCHOR_DIR": "rendered by the anchor CronJob",
    "SUNDER_SEALER_HEALTH_ADDR": "rendered by the sealer Deployment",
    "SUNDER_KEYSTORE_PATH": "the file driver is not a supported multi-replica deployment",
    # Single-instance only: the chart deliberately does not offer them.
    "SUNDER_FILES_DIR": "local file storage is single-instance; the chart offers s3 only",
}

ref = open("docs/CONFIG.md").read()
documented = set(re.findall(r"`(SUNDER_[A-Z0-9_]+)`", ref))
helm = ""
for f in ("deploy/helm/sunder/templates/_helpers.tpl",
          "deploy/helm/sunder/templates/deployment.yaml",
          "deploy/helm/sunder/templates/cronjobs.yaml",
          "deploy/helm/sunder/templates/sealer.yaml",
          "deploy/helm/sunder/values.yaml"):
    helm += open(f).read()

missing = sorted(v for v in documented if v not in helm and v not in EXEMPT)
if missing:
    print("::error::documented variables an operator cannot set through the Helm chart:")
    for v in missing:
        print("   ", v)
    print("  Add them to values.yaml + _helpers.tpl, or exempt them with a reason in this script.")
    sys.exit(1)
print(f"  {len(documented)} documented variables, {len(EXEMPT)} exempt with a stated reason, 0 unreachable")
PY

# ------------------------------------------------------------- postman ------
section "postman: every documented route has a request"
python3 - <<'PY' || fail=1
import json, re, sys, yaml

# Routes deliberately absent from the collection, with the reason.
EXEMPT = {
    ("get", "/metrics"): "present, but scraped by Prometheus rather than clicked",
    ("post", "/portal/api/start"): "browser-facing portal flow, driven by the portal UI",
    ("post", "/portal/api/session"): "browser-facing portal flow",
    ("get", "/portal/api/me"): "browser-facing portal flow",
    ("post", "/portal/api/consent"): "browser-facing portal flow",
    ("post", "/portal/api/erase"): "browser-facing portal flow",
    ("post", "/portal/api/erase/confirm"): "browser-facing portal flow",
    ("post", "/portal/api/logout"): "browser-facing portal flow",
}

spec = yaml.safe_load(open("api/openapi.yaml"))
col = json.load(open("api/sunder.postman_collection.json"))

seen = set()
def walk(x):
    if isinstance(x, dict):
        if "request" in x:
            u = x["request"].get("url")
            raw = u.get("raw") if isinstance(u, dict) else u
            p = re.sub(r"^\{\{baseUrl\}\}", "", str(raw)).split("?")[0]
            seen.add((x["request"]["method"].lower(), re.sub(r"\{\{[^}]+\}\}", "{}", p)))
        for v in x.values():
            walk(v)
    elif isinstance(x, list):
        for v in x:
            walk(v)
walk(col)

missing = []
total = 0
for path, ops in spec["paths"].items():
    shape = re.sub(r"\{[^}]+\}", "{}", path)
    for m in ops:
        if m not in ("get", "post", "put", "delete", "patch"):
            continue
        total += 1
        if (m, path) in EXEMPT:
            continue
        # A collection request may spell a path parameter as a literal
        # (".../attributes/email"), so compare segment counts as well.
        hit = any(sm == m and (sp == shape or
                               (sp.count("/") == shape.count("/") and
                                sp.split("/")[:3] == shape.split("/")[:3]))
                  for sm, sp in seen)
        if not hit:
            missing.append(f"{m.upper()} {path}")

if missing:
    print("::error::documented routes with no Postman request:")
    for x in sorted(missing):
        print("   ", x)
    print("  Add a request to api/sunder.postman_collection.json, or exempt it with a reason.")
    sys.exit(1)
print(f"  {total} documented operations, {len(EXEMPT)} exempt with a stated reason, 0 uncovered")
PY

# ----------------------------------------------------------------- sdk ------
section "sdk: a method wrapped by some SDKs is wrapped by all six"
python3 - <<'PY' || fail=1
import re, sys

SDKS = {
    "go":     "sdks/go/api.go sdks/go/sunder.go",
    "ts":     "sdks/typescript/src/index.ts",
    "python": "sdks/python/sunder_client/__init__.py",
    "php":    "sdks/php/src/SunderClient.php",
    "java":   "sdks/java/src/main/java/io/sunderid/client/SunderClient.java",
    "dotnet": "sdks/dotnet/src/SunderId.Client/SunderClient.cs",
}
# One row per capability: the regex that proves each SDK exposes it. The
# names differ per language, which is exactly why this is a table and not a
# grep for one string.
CAPABILITIES = {
    "registerContact":     r"[Rr]egisterContact|register_contact",
    "issueScopedCid":      r"[Ii]ssueScopedC[Ii][Dd]|issue_scoped_cid",
    "lookup":              r"[Ll]ookupByEmail|lookup_by_email",
    "getAttribute":        r"[Gg]etAttribute|get_attribute",
    "issueOti":            r"[Ii]ssueOti|[Ii]ssueOTI|issue_oti",
    "verifyOti":           r"[Vv]erifyOti|[Vv]erifyOTI|verify_oti",
    "setConsent":          r"[Ss]etConsent|set_consent",
    "getConsent":          r"[Gg]etConsent|get_consent",
    "dsrAccess":           r"[Dd][Ss][Rr][Aa]ccess|dsr_access",
    "dsrExport":           r"[Dd][Ss][Rr][Ee]xport|dsr_export",
    "dsrErase":            r"[Dd][Ss][Rr][Ee]rase|dsr_erase",
    "tokenize":            r"[Tt]okenize\(|[Tt]okenizeAsync|def tokenize",
    "detokenize":          r"[Dd]etokenize\(|[Dd]etokenizeAsync|def detokenize",
    "deleteToken":         r"[Dd]eleteToken|delete_token",
    "tokenizeBulk":        r"[Tt]okenizeBulk|tokenize_bulk",
    "detokenizeBulk":      r"[Dd]etokenizeBulk|detokenize_bulk",
    "uploadFile":          r"[Uu]ploadFile|upload_file",
    "listFiles":           r"[Ll]istFiles|list_files",
    "downloadFile":        r"[Dd]ownloadFile|download_file",
    "deleteFile":          r"[Dd]eleteFile|delete_file",
    "createShare":         r"[Cc]reateShare|create_share",
    "fetchShare":          r"[Ff]etchShare|fetch_share",
    "revokeShare":         r"[Rr]evokeShare|revoke_share",
    "link":                r"func \(c \*Client\) Link|LinkAsync|def link|function link|public void link|async link",
    "unlink":              r"[Uu]nlink",
    "listLinks":           r"[Ll]istLinks|list_links",
    "listVersions":        r"[Ll]istVersions|list_versions",
    "getVersionAttribute": r"[Gg]etVersionAttribute|get_version_attribute",
    "storeExternalClaim":  r"[Ss]toreExternalClaim|store_external_claim",
    "unlock":              r"[Uu]nlock\(|UnlockAsync|def unlock",
    "userId":              r"[Uu]serId|user_id|[Uu]serID",
}

src = {}
for name, files in SDKS.items():
    src[name] = "".join(open(f).read() for f in files.split())

gaps = []
for cap, pat in CAPABILITIES.items():
    have = [n for n in SDKS if re.search(pat, src[n])]
    if have and len(have) != len(SDKS):
        gaps.append((cap, sorted(set(SDKS) - set(have))))

if gaps:
    print("::error::capabilities present in some SDKs and missing from others:")
    for cap, missing in gaps:
        print(f"    {cap}: missing from {', '.join(missing)}")
    print("  Six SDKs with different surfaces is a support burden, not a feature.")
    sys.exit(1)
print(f"  {len(CAPABILITIES)} capabilities, present in all {len(SDKS)} SDKs")
PY

# -------------------------------------------------------------- mirror ------
section "mirror: docs/CONFIG.md and the docs-site page agree"
python3 - <<'PY' || fail=1
import re, sys

# Variables intentionally absent from the docs-site page, with the reason.
EXEMPT = {
    "SUNDER_TEST_TSA": "test-only switch, not operator configuration",
    "SUNDER_TEST_GETENV_DEFAULT": "test-only switch",
}

ref = set(re.findall(r"`(SUNDER_[A-Z0-9_]+)`", open("docs/CONFIG.md").read()))
site_text = open("docs-site/docs/install/configuration.md").read()
missing = sorted(v for v in ref if v not in site_text and v not in EXEMPT)
if missing:
    print("::error::variables in docs/CONFIG.md that the docs-site reference does not mention:")
    for v in missing:
        print("   ", v)
    print("  The published site is what an operator reads. Mirror them, or exempt with a reason.")
    sys.exit(1)
print(f"  {len(ref)} variables in the reference, all present on the published page")
PY

# ------------------------------------------------------- corruption --------
section "tests: data is corrupted by mutation, never by assignment"
python3 - <<'PYEOF2' || fail=1
import re, subprocess, sys

# A test that "corrupts" a byte by ASSIGNING a constant is a no-op whenever
# the byte already held that constant. Three sites in this tree used
# overlay(x placing 0xff from N for 1); one took a CI leg down with a
# 1-in-256 failure that reproduced in no local run, and the other two were
# the same bug waiting its turn. The assertion still passed - on an intact
# payload, which is a test passing for the wrong reason.
#
# Mutation (XOR) corrupts whatever the byte held.
res = subprocess.run(
    ["grep", "-rn", "--include=*_test.go", "--include=*.go", "-E",
     "overlay[(].*placing", "internal/", "cmd/", "benchmark/"],
    capture_output=True, text=True)
bad = [ln for ln in res.stdout.splitlines() if ln.strip()]
if bad:
    print("::error::data corrupted by ASSIGNMENT - a no-op when the byte already holds that value:")
    for b in bad:
        print("   ", b[:150])
    print("  Use XOR: set_byte(x, N, get_byte(x, N) # 255), or in Go: b[i] ^= 0xFF")
    sys.exit(1)
print("  no assignment-style corruption in tests")
PYEOF2

echo
echo "== demos: every shipped demo script runs in CI"
# demo/escalation.sh shipped, was linked from docs/API.md as something a
# reader can run, and returned 403 at step 2 for however long it had been
# out of sync with the server - because no job ever executed it. A demo that
# nothing runs is documentation of a system that may not exist.
#
# lib.sh is a sourced helper, not a walkthrough, so it is the one exemption.
python3 - <<'PYEOF3' || fail=1
import re, subprocess, sys

EXEMPT = {
    "lib.sh": "a sourced helper, not a walkthrough - it has no main()",
}

scripts = sorted(
    p.split("/")[-1]
    for p in subprocess.run(["ls"], cwd="demo", capture_output=True, text=True).stdout.split()
    if p.endswith(".sh")
)
ci = open(".github/workflows/ci.yml").read()

missing, exempted = [], []
for s in scripts:
    if s in EXEMPT:
        exempted.append(f"{s} ({EXEMPT[s]})")
        continue
    stem = s[:-3]
    # Either named with its path, or by stem inside a for-loop list.
    if f"demo/{s}" in ci or re.search(rf"\b{re.escape(stem)}\b", ci):
        continue
    missing.append(s)

if not scripts:
    print("::error::no demo scripts found - this check has stopped checking")
    sys.exit(1)
if missing:
    print("::error::demo scripts that no CI job runs:")
    for m in missing:
        print("   demo/" + m)
    print("  Add a step to the e2e-demo job (with whatever credentials it needs),")
    print("  or add it to EXEMPT here with the reason it is not runnable.")
    sys.exit(1)
print(f"  {len(scripts)} demo script(s), {len(exempted)} exempt with a stated reason, 0 unrun")
for e in exempted:
    print("    exempt:", e)
PYEOF3

echo
if [ "$fail" -ne 0 ]; then
  echo "::error::artifact coverage check failed - a feature is missing from an artifact that describes it"
  exit 1
fi
echo "artifact coverage: helm, postman, sdk parity, the docs mirror and the demo scripts all complete"
