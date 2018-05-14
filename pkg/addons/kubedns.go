package addons

import "yunion.io/yke/pkg/templates"

const (
	KubeDNSImage           = "KubeDNSImage"
	DNSMasqImage           = "DNSMasqImage"
	KubeDNSSidecarImage    = "KubednsSidecarImage"
	KubeDNSAutoScalerImage = "KubeDNSAutoScalerImage"
	KubeDNSServer          = "ClusterDNSServer"
	KubeDNSClusterDomain   = "ClusterDomain"
)

func GetKubeDNSManifest(kubeDNSConfig map[string]string) (string, error) {

	return templates.CompileTemplateFromMap(templates.KubeDNSTemplate, kubeDNSConfig)
}
