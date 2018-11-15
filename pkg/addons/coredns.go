package addons

import "yunion.io/x/yke/pkg/templates"

func GetCoreDNSManifest(CoreDNSConfig interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.CoreDNSTemplate, CoreDNSConfig)
}
