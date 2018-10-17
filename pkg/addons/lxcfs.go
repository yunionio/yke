package addons

import "yunion.io/x/yke/pkg/templates"

func GetYunionLXCFSManifest(config interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.YunionLXCFSTemplate, config)
}
