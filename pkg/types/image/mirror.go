package image

import (
	"fmt"
	"strings"
)

const (
	YunionMirror = "registry.cn-beijing.aliyuncs.com/yunionio"
)

var Mirrors = map[string]string{}

func Mirror(image string) string {
	orig := image
	if strings.HasPrefix(image, "weaveworks") {
		return image
	}

	image = strings.Replace(image, "gcr.io/google_containers", YunionMirror, 1)
	image = strings.Replace(image, "quay.io/coreos/", fmt.Sprintf("%s/coreos-", YunionMirror), 1)
	image = strings.Replace(image, "quay.io/calico/", "rancher/calico-", 1)
	image = strings.Replace(image, "k8s.gcr.io/", fmt.Sprintf("%s/nginx-ingress-controller-", YunionMirror), 1)
	image = strings.Replace(image, "plugins/docker", "rancher/jenkins-plugins-docker", 1)
	image = strings.Replace(image, "kibana", "rancher/kibana", 1)
	image = strings.Replace(image, "jenkins/", "rancher/jenkins-", 1)
	image = strings.Replace(image, "alpine/git", "rancher/alpine-git", 1)
	image = strings.Replace(image, "quay.io/pires", "rancher", 1)
	image = strings.Replace(image, "quay.io/k8scsi", YunionMirror, 1)
	image = strings.Replace(image, "yunion/", fmt.Sprintf("%s/", YunionMirror), 1)
	image = strings.Replace(image, "zexi/", fmt.Sprintf("%s/", YunionMirror), 1)
	image = strings.Replace(image, "rancher/", fmt.Sprintf("%s/", YunionMirror), 1)
	Mirrors[image] = orig

	return image
}
