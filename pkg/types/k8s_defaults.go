package types

import (
	"fmt"
	"strings"

	"yunion.io/x/yke/pkg/types/image"
)

const (
	DefaultK8s = "v1.12.3-rancher1-1"
)

var (
	m = image.Mirror

	// K8sVersionsCurrent are the latest versions available for installation
	K8sVersionsCurrent = []string{
		"v1.10.5-rancher1-2",
		"v1.11.3-rancher1-1",
		"v1.12.3-rancher1-1",
	}

	// K8sVersionToSystemImages is dynamically populated on init() with the latest versions
	K8sVersionToSystemImages map[string]SystemImages

	// K8sVersionServiceOptions - service options per k8s version
	K8sVersionServiceOptions = map[string]KubernetesServicesOptions{
		"v1.12": {
			KubeAPI: map[string]string{
				"tls-cipher-suites":        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"enable-admission-plugins": "ServiceAccount,NamespaceLifecycle,LimitRanger,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota,DefaultTolerationSeconds,Initializers",
			},
			Kubelet: map[string]string{
				"tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"cadvisor-port":     "",
			},
		},
		"v1.11": {
			KubeAPI: map[string]string{
				"tls-cipher-suites":        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"enable-admission-plugins": "ServiceAccount,NamespaceLifecycle,LimitRanger,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota,DefaultTolerationSeconds,Initializers",
			},
			Kubelet: map[string]string{
				"tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			},
		},
		"v1.10": {
			KubeAPI: map[string]string{
				"tls-cipher-suites":        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
				"endpoint-reconciler-type": "lease",
				"enable-admission-plugins": "ServiceAccount,NamespaceLifecycle,LimitRanger,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota,DefaultTolerationSeconds,Initializers",
			},
			Kubelet: map[string]string{
				"tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
			},
		},
	}

	AllK8sVersions = map[string]SystemImages{
		"v1.10.5-rancher1-2": {
			Etcd:                      m("quay.io/coreos/etcd:v3.2.18"),
			Kubernetes:                m("rancher/hyperkube:v1.10.5-rancher1"),
			Alpine:                    m("yunion/yke-tools:v0.1.13"),
			NginxProxy:                m("yunion/yke-tools:v0.1.13"),
			CertDownloader:            m("yunion/yke-tools:v0.1.13"),
			KubernetesServicesSidecar: m("yunion/yke-tools:v0.1.13"),
			KubeDNS:                   m("gcr.io/google_containers/k8s-dns-kube-dns-amd64:1.14.8"),
			DNSmasq:                   m("gcr.io/google_containers/k8s-dns-dnsmasq-nanny-amd64:1.14.8"),
			KubeDNSSidecar:            m("gcr.io/google_containers/k8s-dns-sidecar-amd64:1.14.8"),
			KubeDNSAutoscaler:         m("gcr.io/google_containers/cluster-proportional-autoscaler-amd64:1.0.0"),
			CoreDNS:                   m("yunion/coredns:1.2.6"),
			YunionCNI:                 m("yunion/cni:v2.3.1"),
			CSIAttacher:               m("quay.io/k8scsi/csi-attacher:v0.4.0"),
			CSIProvisioner:            m("quay.io/k8scsi/csi-provisioner:v0.4.0"),
			CSIRegistrar:              m("quay.io/k8scsi/driver-registrar:v0.4.0"),
			YunionCSI:                 m("yunion/csi-plugin:v0.3.2"),
			PodInfraContainer:         m("gcr.io/google_containers/pause-amd64:3.1"),
			Ingress:                   m("rancher/nginx-ingress-controller:0.16.2-rancher1"),
			IngressBackend:            m("k8s.gcr.io/defaultbackend:1.4"),
			MetricsServer:             m("gcr.io/google_containers/metrics-server-amd64:v0.2.1"),
			Tiller:                    m("yunion/tiller:v2.9.1"),
			Heapster:                  m("yunion/heapster-amd64:v1.5.4"),
			YunionCloudMonitor:        m("yunion/cloudmon:latest"),
		},
		"v1.11.3-rancher1-1": {
			Etcd:                      m("quay.io/coreos/etcd:v3.2.18"),
			Kubernetes:                m("rancher/hyperkube:v1.11.3-rancher1"),
			Alpine:                    m("yunion/yke-tools:v0.1.13"),
			NginxProxy:                m("yunion/yke-tools:v0.1.13"),
			CertDownloader:            m("yunion/yke-tools:v0.1.13"),
			KubernetesServicesSidecar: m("yunion/yke-tools:v0.1.13"),
			KubeDNS:                   m("gcr.io/google_containers/k8s-dns-kube-dns-amd64:1.14.10"),
			DNSmasq:                   m("gcr.io/google_containers/k8s-dns-dnsmasq-nanny-amd64:1.14.10"),
			KubeDNSSidecar:            m("gcr.io/google_containers/k8s-dns-sidecar-amd64:1.14.10"),
			KubeDNSAutoscaler:         m("gcr.io/google_containers/cluster-proportional-autoscaler-amd64:1.0.0"),
			CoreDNS:                   m("yunion/coredns:1.2.6"),
			YunionCNI:                 m("yunion/cni:v2.3.1"),
			CSIAttacher:               m("quay.io/k8scsi/csi-attacher:v0.4.0"),
			CSIProvisioner:            m("quay.io/k8scsi/csi-provisioner:v0.4.0"),
			CSIRegistrar:              m("quay.io/k8scsi/driver-registrar:v0.4.0"),
			YunionCSI:                 m("yunion/csi-plugin:v0.3.2"),
			PodInfraContainer:         m("gcr.io/google_containers/pause-amd64:3.1"),
			Ingress:                   m("rancher/nginx-ingress-controller:0.16.2-rancher1"),
			IngressBackend:            m("k8s.gcr.io/defaultbackend:1.4"),
			MetricsServer:             m("gcr.io/google_containers/metrics-server-amd64:v0.2.1"),
			Tiller:                    m("yunion/tiller:v2.11.0"),
			Heapster:                  m("yunion/heapster-amd64:v1.5.4"),
			YunionCloudMonitor:        m("yunion/cloudmon:latest"),
		},
		"v1.12.3-rancher1-1": {
			Etcd:                      m("quay.io/coreos/etcd:v3.2.24"),
			Kubernetes:                m("rancher/hyperkube:v1.12.3-rancher1"),
			Alpine:                    m("yunion/yke-tools:v0.1.13"),
			NginxProxy:                m("yunion/yke-tools:v0.1.13"),
			CertDownloader:            m("yunion/yke-tools:v0.1.13"),
			KubernetesServicesSidecar: m("yunion/yke-tools:v0.1.13"),
			KubeDNS:                   m("gcr.io/google_containers/k8s-dns-kube-dns-amd64:1.14.13"),
			DNSmasq:                   m("gcr.io/google_containers/k8s-dns-dnsmasq-nanny-amd64:1.14.13"),
			KubeDNSSidecar:            m("gcr.io/google_containers/k8s-dns-sidecar-amd64:1.14.13"),
			KubeDNSAutoscaler:         m("gcr.io/google_containers/cluster-proportional-autoscaler-amd64:1.0.0"),
			CoreDNS:                   m("yunion/coredns:1.2.6"),
			YunionCNI:                 m("yunion/cni:v2.3.1"),
			CSIAttacher:               m("quay.io/k8scsi/csi-attacher:v0.4.0"),
			CSIProvisioner:            m("quay.io/k8scsi/csi-provisioner:v0.4.0"),
			CSIRegistrar:              m("quay.io/k8scsi/driver-registrar:v0.4.0"),
			YunionCSI:                 m("yunion/csi-plugin:v0.3.2"),
			PodInfraContainer:         m("gcr.io/google_containers/pause-amd64:3.1"),
			Ingress:                   m("rancher/nginx-ingress-controller:0.16.2-rancher1"),
			IngressBackend:            m("k8s.gcr.io/defaultbackend:1.4"),
			MetricsServer:             m("gcr.io/google_containers/metrics-server-amd64:v0.3.1"),
			Tiller:                    m("yunion/tiller:v2.11.0"),
			Heapster:                  m("yunion/heapster-amd64:v1.5.4"),
			YunionCloudMonitor:        m("yunion/cloudmon:latest"),
		},
	}
)

func init() {
	badVersions := map[string]bool{
		"v1.9.7-rancher1":    true,
		"v1.10.1-rancher1":   true,
		"v1.8.11-rancher1":   true,
		"v1.8.10-rancher1-1": true,
	}
	if K8sVersionToSystemImages != nil {
		panic("Do not initialize or add values to K8sVersionToSystemImages")
	}

	K8sVersionToSystemImages = map[string]SystemImages{}

	for version, images := range AllK8sVersions {
		if badVersions[version] {
			continue
		}

		longName := fmt.Sprintf("%s/hyperkube:%s", image.YunionMirror, version)
		if !strings.HasPrefix(longName, images.Kubernetes) {
			panic(fmt.Sprintf("For K8s version %q, the Kubernetes image tag should be a substring of %q, currently it is %q", version, version, images.Kubernetes))
		}
	}

	for _, latest := range K8sVersionsCurrent {
		images, ok := AllK8sVersions[latest]
		if !ok {
			panic("K8s version is not found in AllK8sVersions map")
		}
		K8sVersionToSystemImages[latest] = images
	}

	if _, ok := K8sVersionToSystemImages[DefaultK8s]; !ok {
		panic("Default K8s version " + DefaultK8s + " is not found in K8sVersionsCurrent list")
	}
}
