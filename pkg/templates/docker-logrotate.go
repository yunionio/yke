package templates

const (
	DockerLogrotateConfig = `
{{.DockerGraphDir}}/containers/*/*.log {
    rotate 5
    daily
    missingok
    dateext
    copytruncate
    notifempty
    compress
    size 10M
}`
)
