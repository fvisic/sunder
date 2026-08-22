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
