package addons

import "yunion.io/yke/pkg/templates"

func GetAddonsExcuteJob(addonName, nodeName, image string) (string, error) {
	jobConfig := map[string]string{
		"AddonName": addonName,
		"NodeName":  nodeName,
		"Image":     image,
	}
	return templates.CompileTemplateFromMap(templates.JobDeployerTemplate, jobConfig)
}
