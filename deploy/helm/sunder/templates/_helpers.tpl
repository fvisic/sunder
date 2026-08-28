{{- define "sunder.labels" -}}
app.kubernetes.io/name: sunder
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- /*
  One security baseline for EVERY workload. The Deployment had both blocks,
  the anchor and retention CronJobs only the pod-level one, and the sealer
  Deployment and verify-audit CronJob neither - so under `restricted` Pod
  Security Admission the Deployment is rejected visibly while the CronJob is
  admitted and only its Jobs fail at creation time, silently stopping daily
  tamper-evidence verification (OPS-CLI-CONFIG-11).
*/}}
{{- define "sunder.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
seccompProfile: {type: RuntimeDefault}
{{- end }}

{{- define "sunder.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: {drop: [ALL]}
{{- end }}

{{- define "sunder.env" -}}
- name: SUNDER_DB_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.existingSecret }}
      key: SUNDER_DB_URL
{{- if and (eq .Values.keystore.type "vault") (not .Values.signer.enabled) }}
- name: SUNDER_KEYSTORE
  value: vault
- name: SUNDER_VAULT_ADDR
  value: {{ .Values.keystore.vault.addr | quote }}
- name: SUNDER_VAULT_MOUNT
  value: {{ .Values.keystore.vault.mount | quote }}
- name: SUNDER_VAULT_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.keystore.vault.existingSecret }}
      key: SUNDER_VAULT_TOKEN
{{- end }}
{{- if .Values.redis.addr }}
- name: SUNDER_REDIS_ADDR
  value: {{ .Values.redis.addr | quote }}
- name: SUNDER_REDIS_FAIL_CLOSED
  value: {{ .Values.redis.failClosed | quote }}
{{- if .Values.redis.existingSecret }}
- name: SUNDER_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.existingSecret }}
      key: SUNDER_REDIS_PASSWORD
{{- end }}
{{- end }}
{{- if .Values.signer.enabled }}
- name: SUNDER_SIGNER_SOCKET
  value: /signer/signer.sock
{{- end }}
{{- if .Values.portal.enabled }}
- name: SUNDER_PORTAL_ENABLED
  value: "true"
{{- if .Values.portal.listenPort }}
- name: SUNDER_PORTAL_LISTEN
  value: ":{{ .Values.portal.listenPort }}"
{{- end }}
{{- with .Values.portal.baseUrl }}
- name: SUNDER_PORTAL_BASE_URL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.portal.clientIpHeader }}
- name: SUNDER_PORTAL_CLIENT_IP_HEADER
  value: {{ . | quote }}
{{- end }}
{{- if .Values.portal.trustedProxyHops }}
- name: SUNDER_PORTAL_TRUSTED_PROXY_HOPS
  value: {{ .Values.portal.trustedProxyHops | quote }}
{{- end }}
{{- if .Values.portal.cookieInsecure }}
- name: SUNDER_PORTAL_COOKIE_INSECURE
  value: "true"
{{- end }}
{{- end }}
{{- if .Values.tunables.otiTtl }}
- name: SUNDER_OTI_TTL
  value: {{ .Values.tunables.otiTtl | quote }}
{{- end }}
{{- if .Values.tunables.piiAlg }}
- name: SUNDER_PII_ALG
  value: {{ .Values.tunables.piiAlg | quote }}
{{- end }}
{{- if .Values.tunables.webhookTimeout }}
- name: SUNDER_WEBHOOK_TIMEOUT
  value: {{ .Values.tunables.webhookTimeout | quote }}
{{- end }}
{{- if .Values.tunables.webhookMaxAttempts }}
- name: SUNDER_WEBHOOK_MAX_ATTEMPTS
  value: {{ .Values.tunables.webhookMaxAttempts | quote }}
{{- end }}
{{- if .Values.tunables.deliverInterval }}
- name: SUNDER_DELIVER_INTERVAL
  value: {{ .Values.tunables.deliverInterval | quote }}
{{- end }}
{{- if .Values.tunables.workerClaimTtl }}
- name: SUNDER_WORKER_CLAIM_TTL
  value: {{ .Values.tunables.workerClaimTtl | quote }}
{{- end }}
{{- if .Values.tunables.keyRetireGrace }}
- name: SUNDER_KEY_RETIRE_GRACE
  value: {{ .Values.tunables.keyRetireGrace | quote }}
{{- end }}
{{- with .Values.tunables.apiClientIpHeader }}
- name: SUNDER_API_CLIENT_IP_HEADER
  value: {{ . | quote }}
{{- end }}
{{- with .Values.tunables.rekeyBatch }}
- name: SUNDER_REKEY_BATCH
  value: {{ . | quote }}
{{- end }}
{{- with .Values.tunables.maxCascadeChildren }}
- name: SUNDER_MAX_CASCADE_CHILDREN
  value: {{ . | quote }}
{{- end }}
{{- if .Values.keystore.allowMint }}
- name: SUNDER_KEYSTORE_ALLOW_MINT
  value: "true"
{{- end }}
{{- if .Values.search.fuzzyName }}
- name: SUNDER_SEARCH_FUZZY_NAME
  value: "true"
{{- end }}
{{- if .Values.search.phoneSuffix }}
- name: SUNDER_SEARCH_PHONE_SUFFIX
  value: "true"
{{- end }}
{{- if .Values.search.unlock }}
- name: SUNDER_SEARCH_UNLOCK
  value: "true"
{{- end }}
{{- if .Values.shares.public }}
- name: SUNDER_SHARES_PUBLIC
  value: "true"
{{- end }}
{{- with .Values.versions.keep }}
- name: SUNDER_VERSIONS_KEEP
  value: {{ . | quote }}
{{- end }}
{{- with .Values.versions.ttl }}
- name: SUNDER_VERSIONS_TTL
  value: {{ . | quote }}
{{- end }}
{{- if .Values.files.storage }}
{{- if ne .Values.files.storage "s3" }}
{{- fail "files.storage must be \"s3\": the local driver keeps ciphertext in a per-process directory while its metadata and wrapped DEK live in the shared database, so a second replica answers a download with 200 and an empty body" }}
{{- end }}
- name: SUNDER_FILES_STORAGE
  value: {{ .Values.files.storage | quote }}
{{- with .Values.files.maxMB }}
- name: SUNDER_FILES_MAX_MB
  value: {{ . | quote }}
{{- end }}
{{- with .Values.files.maxConcurrentUploads }}
- name: SUNDER_FILES_MAX_CONCURRENT_UPLOADS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.files.s3.endpoint }}
- name: SUNDER_FILES_S3_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- with .Values.files.s3.bucket }}
- name: SUNDER_FILES_S3_BUCKET
  value: {{ . | quote }}
{{- end }}
{{- with .Values.files.s3.region }}
- name: SUNDER_FILES_S3_REGION
  value: {{ . | quote }}
{{- end }}
{{- if .Values.files.s3.pathStyle }}
- name: SUNDER_FILES_S3_PATH_STYLE
  value: "true"
{{- end }}
{{- with .Values.files.s3.existingSecret }}
- name: SUNDER_FILES_S3_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ . }}
      key: SUNDER_FILES_S3_ACCESS_KEY
- name: SUNDER_FILES_S3_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ . }}
      key: SUNDER_FILES_S3_SECRET_KEY
{{- end }}
{{- end }}
{{- include "sunder.auditEnv" . }}
{{- if .Values.audit.sealer.enabled }}
- name: SUNDER_AUDIT_SEAL_EXTERNAL
  value: "true"
{{- end }}
{{- if .Values.metrics.existingSecret }}
- name: SUNDER_METRICS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.metrics.existingSecret }}
      key: SUNDER_METRICS_TOKEN
{{- end }}
{{- if .Values.tls.enabled }}
- name: SUNDER_TLS_CERT
  value: /tls/tls.crt
- name: SUNDER_TLS_KEY
  value: /tls/tls.key
{{- if .Values.tls.mtlsSecretName }}
- name: SUNDER_MTLS_CA
  value: /mtls/ca.crt
{{- end }}
{{- end }}
{{- end }}

{{/* Env for the signer sidecar: keystore only - no database, no service config. */}}
{{- define "sunder.signerEnv" -}}
{{- if eq .Values.keystore.type "vault" }}
- name: SUNDER_KEYSTORE
  value: vault
- name: SUNDER_VAULT_ADDR
  value: {{ .Values.keystore.vault.addr | quote }}
- name: SUNDER_VAULT_MOUNT
  value: {{ .Values.keystore.vault.mount | quote }}
- name: SUNDER_VAULT_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.keystore.vault.existingSecret }}
      key: SUNDER_VAULT_TOKEN
{{- end }}
{{- end }}

{{/* The audit posture, shared VERBATIM by every workload that reads it: the
API pods, the dedicated sealer (which must run with the same tunables the
operator set - not hard-coded defaults) and the verify-audit CronJob (whose
verdict branches on the sealing/read mode: a job seeing "async" under a sync
posture would skip the stranded-rows hard failure and report success where a
hand-run verify reports BROKEN). SEAL_EXTERNAL is deliberately NOT here - it
is an API-pod statement about who seals, appended separately. */}}
{{- define "sunder.auditEnv" -}}
{{- with .Values.audit.sealing }}
- name: SUNDER_AUDIT_SEALING
  value: {{ . | quote }}
{{- end }}
{{- with .Values.audit.reads }}
- name: SUNDER_AUDIT_READS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.audit.sealInterval }}
- name: SUNDER_AUDIT_SEAL_INTERVAL
  value: {{ . | quote }}
{{- end }}
{{- with .Values.audit.sealDelay }}
- name: SUNDER_AUDIT_SEAL_DELAY
  value: {{ . | quote }}
{{- end }}
{{- with .Values.audit.sealBatch }}
- name: SUNDER_AUDIT_SEAL_BATCH
  value: {{ . | quote }}
{{- end }}
{{- with .Values.audit.staleUnsealed }}
- name: SUNDER_AUDIT_STALE_UNSEALED
  value: {{ . | quote }}
{{- end }}
{{- end }}
