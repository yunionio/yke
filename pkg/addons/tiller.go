package addons

import "yunion.io/x/yke/pkg/templates"

func GetTillerManifest(config interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.HelmTillerTemplate, config)
}
