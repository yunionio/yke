package addons

import "yunion.io/x/yke/pkg/templates"

func GetKubeDNSManifest(kubeDNSConfig interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.KubeDNSTemplate, kubeDNSConfig)
}
