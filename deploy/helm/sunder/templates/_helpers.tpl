{{- define "sunder.labels" -}}
app.kubernetes.io/name: sunder
app.kubernetes.io/instance: {{ .Release.Name }}
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
