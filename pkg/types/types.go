package types

type KubernetesEngineConfig struct {
	// Kubernetes nodes
	Nodes []ConfigNode `yaml:"nodes" json:"nodes"`
	// Kubernetes components
	Services ConfigServices `yaml:"services" json:"services"`
	// Network configuration used in the kubernetes cluster
	Network NetworkConfig `yaml:"network" json:"network"`
	// Authentication configuration used in the cluster (default: x509)
	Authentication AuthnConfig `yaml:"authentication" json:"authentication"`
	// YAML manifest for user provided addons to be deployed on the cluster
	Addons string `yaml:"addons" json:"addons"`
	// List of urls or paths for addons
	AddonsInclude []string `yaml:"addons_include" json:"addonsInclude"`
	// List of images used internally for proxy, cert downlaod and kubedns
	SystemImages SystemImages `yaml:"system_images" json:"systemImages"`
	// SSH Private Key Path
	SSHKeyPath string `yaml:"ssh_key_path" json:"sshKeyPath"`
	// SSH Agent Auth enable
	SSHAgentAuth bool `yaml:"ssh_agent_auth" json:"sshAgentAuth"`
	// Authorization mode configuration used in the cluster
	Authorization AuthzConfig `yaml:"authorization" json:"authorization"`
	// Enable/disable strict docker version checking
	IgnoreDockerVersion bool `yaml:"ignore_docker_version" json:"ignoreDockerVersion"`
	// Kubernetes version to use (if kubernetes image is specifed, image version takes precedence)
	Version string `yaml:"kubernetes_version" json:"kubernetesVersion"`
	// List of private registries and their credentials
	PrivateRegistries []PrivateRegistry `yaml:"private_registries" json:"privateRegistries"`
	// Ingress controller used in the cluster
	Ingress IngressConfig `yaml:"ingress" json:"ingress"`
	// Cluster Name used in the kube config
	ClusterName string `yaml:"cluster_name" json:"clusterName"`
	// Cloud Provider options
	CloudProvider CloudProvider `yaml:"cloud_provider" json:"cloudProvider"`
	// WebhookConfig options
	WebhookAuth WebhookAuth `yaml:"webhook_auth" json:"webhookAuth"`
}

type PrivateRegistry struct {
	// URL for the registry
	URL string `yaml:"url" json:"url"`
	// User name for registry access
	User string `yaml:"user" json:"user"`
	// Password for registry access
	Password string `yaml:"password" json:"password"`
}

type SystemImages struct {
	// etcd image
	Etcd string `yaml:"etcd" json:"etcd"`
	// Alpine image
	Alpine string `yaml:"alpine" json:"alpine"`
	// rke-nginx-proxy image
	NginxProxy string `yaml:"nginx_proxy" json:"nginxProxy"`
	// rke-cert-deployer image
	CertDownloader string `yaml:"cert_downloader" json:"certDownloader"`
	// rke-service-sidekick image
	KubernetesServicesSidecar string `yaml:"kubernetes_services_sidecar" json:"kubernetesServicesSidecar"`
	// KubeDNS image
	KubeDNS string `yaml:"kubedns" json:"kubedns"`
	// DNSMasq image
	DNSmasq string `yaml:"dnsmasq" json:"dnsmasq"`
	// KubeDNS side car image
	KubeDNSSidecar string `yaml:"kubedns_sidecar" json:"kubednsSidecar"`
	// KubeDNS autoscaler image
	KubeDNSAutoscaler string `yaml:"kubedns_autoscaler" json:"kubednsAutoscaler"`
	// Kubernetes image
	Kubernetes string `yaml:"kubernetes" json:"kubernetes"`
	// Yunion CNI image
	YunionCNI string `yaml:"yunion_cni" json:"yunionCni"`
	/// Yunion k8s keystone WebhookAuth image
	YunionK8sKeystoneAuth string `yaml:"yunion_k8s_keystone_auth" json:"yunionK8sKeystoneAuth"`
	// Pod infra container image
	PodInfraContainer string `yaml:"pod_infra_container" json:"podInfraContainer"`
	// Ingress Controller image
	Ingress string `yaml:"ingress" json:"ingress"`
	// Ingress Controller Backend image
	IngressBackend string `yaml:"ingress_backend" json:"ingressBackend"`
	// Dashboard image
	Dashboard string `yaml:"dashboard" json:"dashboard"`
	// Heapster addon image
	Heapster string `yaml:"heapster" json:"heapster"`
	// Grafana image for heapster addon
	Grafana string `yaml:"grafana" json:"grafana"`
	// Influxdb image for heapster addon
	Influxdb string `yaml:"influxdb" json:"influxdb"`
	// Tiller addon image
	Tiller string `yaml:"tiller" json:"tiller"`
}

type ConfigNode struct {
	// Name of the host provisioned via docker machine
	NodeName string `yaml:"nodeName" json:"nodeName"`
	// IP or FQDN that is fully resolvable and used for SSH communication
	Address string `yaml:"address" json:"address"`
	// Port used for SSH communication
	Port string `yaml:"port" json:"port"`
	// Optional - Internal address that will be used for components communication
	InternalAddress string `yaml:"internal_address" json:"internalAddress"`
	// Node role in kubernetes cluster (controlplane, worker, or etcd)
	Role []string `yaml:"role" json:"role"`
	// Optional - Hostname of the node
	HostnameOverride string `yaml:"hostname_override" json:"hostnameOverride"`
	// SSH usesr that will be used by RKE
	User string `yaml:"user" json:"user"`
	// Optional - Docker socket on the node that will be used in tunneling
	DockerSocket string `yaml:"docker_socket" json:"dockerSocket"`
	// SSH Agent Auth enable
	SSHAgentAuth bool `yaml:"ssh_agent_auth" json:"sshAgentAuth"`
	// SSH Private Key
	SSHKey string `yaml:"ssh_key" json:"sshKey"`
	// SSH Private Key Path
	SSHKeyPath string `yaml:"ssh_key_path" json:"sshKeyPath"`
	// Node Labels
	Labels map[string]string `yaml:"labels" json:"labels"`
}

type ConfigServices struct {
	// Etcd Service
	Etcd ETCDService `yaml:"etcd" json:"etcd"`
	// KubeAPI Service
	KubeAPI KubeAPIService `yaml:"kube-api" json:"kubeApi"`
	// KubeController Service
	KubeController KubeControllerService `yaml:"kube-controller" json:"kubeController"`
	// Scheduler Service
	Scheduler SchedulerService `yaml:"scheduler" json:"scheduler"`
	// Kubelet Service
	Kubelet KubeletService `yaml:"kubelet" json:"kubelet"`
	// KubeProxy Service
	Kubeproxy KubeproxyService `yaml:"kubeproxy" json:"kubeproxy"`

	// YunionWebhookAuth Service
	YunionWebhookAuth YunionWebhookAuthService `yaml:"yunion-webhook-auth" json:"yunionWebhookAuth"`
}

type YunionWebhookAuthService struct {
	// Base service properties
	BaseService   `yaml:",inline" json:",inline"`
	OsAuthURL     string `yaml:"os_auth_url" json:"osAuthURL"`
	OsUsername    string `yaml:"os_username" json:"osUsername"`
	OsPassword    string `yaml:"os_password" json:"osPassword"`
	OsProjectName string `yaml:"os_project_name" json:"osProjectName"`
	OsRegionName  string `yaml:"os_region_name" json:"osRegionName"`
}

type ETCDService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// List of etcd urls
	ExternalURLs []string `yaml:"external_urls" json:"externalUrls"`
	// External CA certificate
	CACert string `yaml:"ca_cert" json:"caCert"`
	// External Client certificate
	Cert string `yaml:"cert" json:"cert"`
	// External Client key
	Key string `yaml:"key" json:"key"`
	// External etcd prefix
	Path string `yaml:"path" json:"path"`
}

type KubeAPIService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// Virtual IP range that will be used by Kubernetes services
	ServiceClusterIPRange string `yaml:"service_cluster_ip_range" json:"serviceClusterIpRange"`
	// Enabled/Disable PodSecurityPolicy
	PodSecurityPolicy bool `yaml:"pod_security_policy" json:"podSecurityPolicy"`
}

type KubeControllerService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// CIDR Range for Pods in cluster
	ClusterCIDR string `yaml:"cluster_cidr" json:"clusterCidr"`
	// Virtual IP range that will be used by Kubernetes services
	ServiceClusterIPRange string `yaml:"service_cluster_ip_range" json:"serviceClusterIpRange"`
}

type KubeletService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// Domain of the cluster (default: "cluster.local")
	ClusterDomain string `yaml:"cluster_domain" json:"clusterDomain"`
	// The image whose network/ipc namespaces containers in each pod will use
	InfraContainerImage string `yaml:"infra_container_image" json:"infraContainerImage"`
	// Cluster DNS service ip
	ClusterDNSServer string `yaml:"cluster_dns_server" json:"clusterDnsServer"`
	// Fail if swap is enabled
	FailSwapOn bool `yaml:"fail_swap_on" json:"failSwapOn"`
}

type KubeproxyService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
}

type SchedulerService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
}

type BaseService struct {
	// Docker image of the service
	Image string `yaml:"image" json:"image"`
	// Extra arguments that are added to the services
	ExtraArgs map[string]string `yaml:"extra_args" json:"extraArgs"`
	// Extra binds added to the nodes
	ExtraBinds []string `yaml:"extra_binds" json:"extraBinds"`
}

type NetworkConfig struct {
	// Network Plugin That will be used in kubernetes cluster
	Plugin string `yaml:"plugin" json:"plugin"`
	// Plugin options to configure network properties
	Options map[string]string `yaml:"options" json:"options"`
}

type AuthnConfig struct {
	// Authentication strategy that will be used in kubernetes cluster
	Strategy string `yaml:"strategy" json:"strategy"`
	// Authentication options
	Options map[string]string `yaml:"options" json:"options"`
	// List of additional hostnames and IPs to include in the api server PKI cert
	SANs []string `yaml:"sans" json:"sans"`
}

type AuthzConfig struct {
	// Authorization mode used by kubernetes
	Mode string `yaml:"mode" json:"mode"`
	// Authorization mode options
	Options map[string]string `yaml:"options" json:"options"`
}

type WebhookAuth struct {
	URL string `yaml:"url" json:"url"`
}

type IngressConfig struct {
	// Ingress controller type used by kubernetes
	Provider string `yaml:"provider" json:"provider"`
	// Ingress controller options
	Options map[string]string `yaml:"options" json:"options"`
	// NodeSelector key pair
	NodeSelector map[string]string `yaml:"node_selector" json:"nodeSelector"`
}

type Plan struct {
	// List of node Plans
	Nodes []ConfigNodePlan `json:"nodes"`
}

type File struct {
	Name     string `json:"name"`
	Contents string `json:"contents"`
}

type ConfigNodePlan struct {
	// Node address
	Address string `json:"address"`
	// map of named processes that should run on the node
	Processes map[string]Process `json:"processes"`
	// List of portchecks that should be open on the node
	PortChecks []PortCheck `json:"portChecks"`
	// List of files to deploy on the node
	Files []File `json:"files"`
	// Node Annotations
	Annotations map[string]string `json:"annotations"`
	// Node Labels
	Labels map[string]string `json:"labels"`
}

type Process struct {
	// Process name, this should be the container name
	Name string `json:"name"`
	// Process Entrypoint command
	Command []string `json:"command"`
	// Process args
	Args []string `json:"args"`
	// Environment variables list
	Env []string `json:"env"`
	// Process docker image
	Image string `json:"image"`
	//AuthConfig for image private registry
	ImageRegistryAuthConfig string `json:"imageRegistryAuthConfig"`
	// Process docker image VolumesFrom
	VolumesFrom []string `json:"volumesFrom"`
	// Process docker container bind mounts
	Binds []string `json:"binds"`
	// Process docker container netwotk mode
	NetworkMode string `json:"networkMode"`
	// Process container restart policy
	RestartPolicy string `json:"restartPolicy"`
	// Process container pid mode
	PidMode string `json:"pidMode"`
	// Run process in privileged container
	Privileged bool `json:"privileged"`
	// Process healthcheck
	HealthCheck HealthCheck `json:"healthCheck"`
}

type HealthCheck struct {
	// Healthcheck URL
	URL string `json:"url"`
}

type PortCheck struct {
	// Portcheck address to check.
	Address string `json:"address"`
	// Port number
	Port int `json:"port"`
	// Port Protocol
	Protocol string `json:"protocol"`
}

type CloudProvider struct {
	// Name of the Cloud Provider
	Name string `yaml:"name" json:"name"`
	// Configuration Options of Cloud Provider
	CloudConfig map[string]string `yaml:"cloud_config" json:"cloudConfig"`
}
