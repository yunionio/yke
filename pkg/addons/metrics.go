package addons

import "yunion.io/x/yke/pkg/templates"

func GetMetricsServerManifest(MetricsServerConfig interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.MetricsServerTemplate, MetricsServerConfig)
}
