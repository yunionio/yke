package addons

import "yunion.io/yke/pkg/templates"

func GetNginxIngressManifest(IngressConfig interface{}) (string, error) {

	return templates.CompileTemplateFromMap(templates.NginxIngressTemplate, IngressConfig)
}
