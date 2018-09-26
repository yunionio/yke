package addons

import (
	"fmt"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/templates"
)

func GetAddonsExcuteJob(addonName, nodeName, image string) (string, error) {
	return getAddonJob(addonName, nodeName, image, false)
}

func GetAddonsDeleteJob(addonName, nodeName, image string) (string, error) {
	return getAddonJob(addonName, nodeName, image, true)
}

func getAddonJob(addonName, nodeName, image string, isDelete bool) (string, error) {
	jobConfig := map[string]string{
		"AddonName": addonName,
		"NodeName":  nodeName,
		"Image":     image,
		"DeleteJob": strconv.FormatBool(isDelete),
	}
	return templates.CompileTemplateFromMap(templates.AddonJobTemplate, jobConfig)
}

func AddonJobExists(addonJobName, kubeConfigPath string, k8sWrapTransport k8s.WrapTransport) (bool, error) {
	k8sClient, err := k8s.NewClient(kubeConfigPath, k8sWrapTransport)
	if err != nil {
		return false, err
	}
	addonJobStatus, err := k8s.GetK8sJobStatus(k8sClient, addonJobName, metav1.NamespaceSystem)
	if err != nil {
		return false, fmt.Errorf("Failed to get job [%s] status: %v", addonJobName, err)
	}
	return addonJobStatus.Created, nil
}
