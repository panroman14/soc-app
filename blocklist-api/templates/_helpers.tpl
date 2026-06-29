{{- define "blocklist-api.name" -}}blocklist-api{{- end -}}

{{- define "blocklist-api.labels" -}}
app.kubernetes.io/name: blocklist-api
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "blocklist-api.secretName" -}}
{{- if .Values.existingSecret -}}{{ .Values.existingSecret }}{{- else -}}blocklist-api{{- end -}}
{{- end -}}
