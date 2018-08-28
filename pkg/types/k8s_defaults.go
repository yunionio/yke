package types

const (
	K8sV18  = "v1.8.10-rancher1-1"
	K8sV19  = "v1.9.5-rancher1-1"
	K8sV110 = "v1.10.0-rancher1-2"
)

var (
	// K8sVersionToSystemImages
	K8sVersionToSystemImages = map[string]SystemImages{
		K8sV18:  v18SystemImages,
		K8sV19:  v19SystemImages,
		K8sV110: v110SystemImages,
	}

	// v18 system images defaults
	v18SystemImages = SystemImages{
		Etcd:                      "rancher/coreos-etcd:v3.0.17",
		Kubernetes:                "rancher/k8s:" + K8sV18,
		Alpine:                    "alpine:latest",
		NginxProxy:                "rancher/rke-nginx-proxy:v0.1.1",
		CertDownloader:            "zexi/yke-cert-deployer:v0.1.1",
		KubernetesServicesSidecar: "yunion/yke-service-sidekick:v0.1.1",
		KubeDNS:                   "rancher/k8s-dns-kube-dns-amd64:1.14.5",
		DNSmasq:                   "rancher/k8s-dns-dnsmasq-nanny-amd64:1.14.5",
		KubeDNSSidecar:            "rancher/k8s-dns-sidecar-amd64:1.14.5",
		KubeDNSAutoscaler:         "rancher/cluster-proportional-autoscaler-amd64:1.0.0",
		YunionCNI:                 "yunion/cni:v1.0.2",
		YunionK8sKeystoneAuth:     "yunion/k8s-keystone-auth:v1.0.0",
		PodInfraContainer:         "rancher/pause-amd64:3.0",
		Ingress:                   "rancher/nginx-ingress-controller:0.10.2-rancher1",
		IngressBackend:            "rancher/nginx-ingress-controller-defaultbackend:1.4",
	}

	// v19 system images defaults
	v19SystemImages = SystemImages{
		Etcd:                      "rancher/coreos-etcd:v3.1.12",
		Kubernetes:                "rancher/k8s:" + K8sV19,
		Alpine:                    "alpine:latest",
		NginxProxy:                "rancher/rke-nginx-proxy:v0.1.1",
		CertDownloader:            "zexi/yke-cert-deployer:v0.1.1",
		KubernetesServicesSidecar: "yunion/yke-service-sidekick:v0.1.1",
		KubeDNS:                   "rancher/k8s-dns-kube-dns-amd64:1.14.7",
		DNSmasq:                   "rancher/k8s-dns-dnsmasq-nanny-amd64:1.14.7",
		KubeDNSSidecar:            "rancher/k8s-dns-sidecar-amd64:1.14.7",
		KubeDNSAutoscaler:         "rancher/cluster-proportional-autoscaler-amd64:1.0.0",
		YunionCNI:                 "yunion/cni:v1.0.2",
		YunionK8sKeystoneAuth:     "yunion/k8s-keystone-auth:v1.0.0",
		PodInfraContainer:         "rancher/pause-amd64:3.0",
		Ingress:                   "rancher/nginx-ingress-controller:0.10.2-rancher1",
		IngressBackend:            "rancher/nginx-ingress-controller-defaultbackend:1.4",
		Grafana:                   "rancher/heapster-grafana-amd64:v4.4.3",
		Heapster:                  "rancher/heapster-amd64:v1.5.0",
		Influxdb:                  "rancher/heapster-influxdb-amd64:v1.3.3",
		Tiller:                    "rancher/tiller:v2.7.2",
		Dashboard:                 "rancher/kubernetes-dashboard-amd64:v1.8.0",
	}

	// v110 system images defaults
	v110SystemImages = SystemImages{
		Etcd:                      "rancher/coreos-etcd:v3.1.12",
		Kubernetes:                "rancher/k8s:" + K8sV110,
		Alpine:                    "alpine:latest",
		NginxProxy:                "rancher/rke-nginx-proxy:v0.1.1",
		CertDownloader:            "zexi/yke-cert-deployer:v0.1.1",
		KubernetesServicesSidecar: "yunion/yke-service-sidekick:v0.1.1",
		KubeDNS:                   "rancher/k8s-dns-kube-dns-amd64:1.14.8",
		DNSmasq:                   "rancher/k8s-dns-dnsmasq-nanny-amd64:1.14.8",
		KubeDNSSidecar:            "rancher/k8s-dns-sidecar-amd64:1.14.8",
		KubeDNSAutoscaler:         "rancher/cluster-proportional-autoscaler-amd64:1.0.0",
		YunionCNI:                 "yunion/cni:v1.0.2",
		YunionK8sKeystoneAuth:     "yunion/k8s-keystone-auth:v1.0.0",
		PodInfraContainer:         "rancher/pause-amd64:3.1",
		Ingress:                   "rancher/nginx-ingress-controller:0.10.2-rancher1",
		IngressBackend:            "rancher/nginx-ingress-controller-defaultbackend:1.4",
		Grafana:                   "rancher/heapster-grafana-amd64:v4.4.3",
		Heapster:                  "rancher/heapster-amd64:v1.5.0",
		Influxdb:                  "rancher/heapster-influxdb-amd64:v1.3.3",
		Tiller:                    "zexi/tiller:v2.9.0",
		Dashboard:                 "rancher/kubernetes-dashboard-amd64:v1.8.3",
	}
)
