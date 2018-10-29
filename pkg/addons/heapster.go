package addons

import "yunion.io/x/yke/pkg/templates"

func GetHeapsterManifest(config interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.HeapsterTemplate, config)
}
