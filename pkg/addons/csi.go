package addons

import "yunion.io/x/yke/pkg/templates"

func GetYunionCSIManifest(config interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.YunionCSITemplate, config)
}
