package addons

import "yunion.io/yke/pkg/templates"

func GetMetricsServerManifest(MetricsServerConfig interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.MetricsServerTemplate, MetricsServerConfig)
}
