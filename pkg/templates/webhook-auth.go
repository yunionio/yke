package templates

const WebhookAuthTemplate = `
apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: "{{.URL}}"
  name: webhook
contexts:
- context:
    cluster: webhook
    user: webhook
  name: webhook
current-context: webhook
kind: Config
preferences: {}
users:
- name: webhook`
