package types

type KubernetesEngineConfig struct {
	// Kubernetes nodes
	Nodes []ConfigNode `yaml:"nodes" json:"nodes,omitempty"`
	// Kubernetes components
	Services ConfigServices `yaml:"services" json:"services,omitempty"`
	// Network configuration used in the kubernetes cluster
	Network NetworkConfig `yaml:"network" json:"network,omitempty"`
	// Authentication configuration used in the cluster (default: x509)
	Authentication AuthnConfig `yaml:"authentication" json:"authentication,omitempty"`
	// YAML manifest for user provided addons to be deployed on the cluster
	Addons string `yaml:"addons" json:"addons,omitempty"`
	// List of urls or paths for addons
	AddonsInclude []string `yaml:"addons_include" json:"addonsInclude,omitempty"`
	// List of images used internally for proxy, cert downlaod and kubedns
	SystemImages SystemImages `yaml:"system_images" json:"systemImages,omitempty"`
	// SSH Private Key Path
	SSHKeyPath string `yaml:"ssh_key_path" json:"sshKeyPath,omitempty"`
	// SSH Agent Auth enable
	SSHAgentAuth bool `yaml:"ssh_agent_auth" json:"sshAgentAuth"`
	// Authorization mode configuration used in the cluster
	Authorization AuthzConfig `yaml:"authorization" json:"authorization,omitempty"`
	// Enable/disable strict docker version checking
	IgnoreDockerVersion bool `yaml:"ignore_docker_version" json:"ignoreDockerVersion"`
	// Kubernetes version to use (if kubernetes image is specifed, image version takes precedence)
	Version string `yaml:"kubernetes_version" json:"kubernetesVersion,omitempty"`
	// List of private registries and their credentials
	PrivateRegistries []PrivateRegistry `yaml:"private_registries" json:"privateRegistries,omitempty"`
	// Ingress controller used in the cluster
	Ingress IngressConfig `yaml:"ingress" json:"ingress,omitempty"`
	// Cluster Name used in the kube config
	ClusterName string `yaml:"cluster_name" json:"clusterName,omitempty"`
	// Cloud Provider options
	CloudProvider CloudProvider `yaml:"cloud_provider" json:"cloudProvider,omitempty"`
	// WebhookConfig options
	WebhookConfigFile string `yaml:"webhook_config_file" json:"webhookConfigFile"`
}

type PrivateRegistry struct {
	// URL for the registry
	URL string `yaml:"url" json:"url,omitempty"`
	// User name for registry access
	User string `yaml:"user" json:"user,omitempty"`
	// Password for registry access
	Password string `yaml:"password" json:"password,omitempty"`
}

type SystemImages struct {
	// etcd image
	Etcd string `yaml:"etcd" json:"etcd,omitempty"`
	// Alpine image
	Alpine string `yaml:"alpine" json:"alpine,omitempty"`
	// rke-nginx-proxy image
	NginxProxy string `yaml:"nginx_proxy" json:"nginxProxy,omitempty"`
	// rke-cert-deployer image
	CertDownloader string `yaml:"cert_downloader" json:"certDownloader,omitempty"`
	// rke-service-sidekick image
	KubernetesServicesSidecar string `yaml:"kubernetes_services_sidecar" json:"kubernetesServicesSidecar,omitempty"`
	// KubeDNS image
	KubeDNS string `yaml:"kubedns" json:"kubedns,omitempty"`
	// DNSMasq image
	DNSmasq string `yaml:"dnsmasq" json:"dnsmasq,omitempty"`
	// KubeDNS side car image
	KubeDNSSidecar string `yaml:"kubedns_sidecar" json:"kubednsSidecar,omitempty"`
	// KubeDNS autoscaler image
	KubeDNSAutoscaler string `yaml:"kubedns_autoscaler" json:"kubednsAutoscaler,omitempty"`
	// Kubernetes image
	Kubernetes string `yaml:"kubernetes" json:"kubernetes,omitempty"`
	// Yunion CNI image
	YunionCNI string `yaml:"yunion_cni" json:"yunionCni,omitempty"`
	// Pod infra container image
	PodInfraContainer string `yaml:"pod_infra_container" json:"podInfraContainer,omitempty"`
	// Ingress Controller image
	Ingress string `yaml:"ingress" json:"ingress,omitempty"`
	// Ingress Controller Backend image
	IngressBackend string `yaml:"ingress_backend" json:"ingressBackend,omitempty"`
	// Dashboard image
	Dashboard string `yaml:"dashboard" json:"dashboard,omitempty"`
	// Heapster addon image
	Heapster string `yaml:"heapster" json:"heapster,omitempty"`
	// Grafana image for heapster addon
	Grafana string `yaml:"grafana" json:"grafana,omitempty"`
	// Influxdb image for heapster addon
	Influxdb string `yaml:"influxdb" json:"influxdb,omitempty"`
	// Tiller addon image
	Tiller string `yaml:"tiller" json:"tiller,omitempty"`
}

type ConfigNode struct {
	// Name of the host provisioned via docker machine
	NodeName string `yaml:"nodeName,omitempty" json:"nodeName,omitempty"`
	// IP or FQDN that is fully resolvable and used for SSH communication
	Address string `yaml:"address" json:"address,omitempty"`
	// Port used for SSH communication
	Port string `yaml:"port" json:"port,omitempty"`
	// Optional - Internal address that will be used for components communication
	InternalAddress string `yaml:"internal_address" json:"internalAddress,omitempty"`
	// Node role in kubernetes cluster (controlplane, worker, or etcd)
	Role []string `yaml:"role" json:"role,omitempty"`
	// Optional - Hostname of the node
	HostnameOverride string `yaml:"hostname_override" json:"hostnameOverride,omitempty"`
	// SSH usesr that will be used by RKE
	User string `yaml:"user" json:"user,omitempty"`
	// Optional - Docker socket on the node that will be used in tunneling
	DockerSocket string `yaml:"docker_socket" json:"dockerSocket,omitempty"`
	// SSH Agent Auth enable
	SSHAgentAuth bool `yaml:"ssh_agent_auth,omitempty" json:"sshAgentAuth,omitempty"`
	// SSH Private Key
	SSHKey string `yaml:"ssh_key" json:"sshKey,omitempty"`
	// SSH Private Key Path
	SSHKeyPath string `yaml:"ssh_key_path" json:"sshKeyPath,omitempty"`
	// Node Labels
	Labels map[string]string `yaml:"labels" json:"labels,omitempty"`
}

type ConfigServices struct {
	// Etcd Service
	Etcd ETCDService `yaml:"etcd" json:"etcd,omitempty"`
	// KubeAPI Service
	KubeAPI KubeAPIService `yaml:"kube-api" json:"kubeApi,omitempty"`
	// KubeController Service
	KubeController KubeControllerService `yaml:"kube-controller" json:"kubeController,omitempty"`
	// Scheduler Service
	Scheduler SchedulerService `yaml:"scheduler" json:"scheduler,omitempty"`
	// Kubelet Service
	Kubelet KubeletService `yaml:"kubelet" json:"kubelet,omitempty"`
	// KubeProxy Service
	Kubeproxy KubeproxyService `yaml:"kubeproxy" json:"kubeproxy,omitempty"`
}

type ETCDService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// List of etcd urls
	ExternalURLs []string `yaml:"external_urls" json:"externalUrls,omitempty"`
	// External CA certificate
	CACert string `yaml:"ca_cert" json:"caCert,omitempty"`
	// External Client certificate
	Cert string `yaml:"cert" json:"cert,omitempty"`
	// External Client key
	Key string `yaml:"key" json:"key,omitempty"`
	// External etcd prefix
	Path string `yaml:"path" json:"path,omitempty"`
}

type KubeAPIService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// Virtual IP range that will be used by Kubernetes services
	ServiceClusterIPRange string `yaml:"service_cluster_ip_range" json:"serviceClusterIpRange,omitempty"`
	// Enabled/Disable PodSecurityPolicy
	PodSecurityPolicy bool `yaml:"pod_security_policy" json:"podSecurityPolicy,omitempty"`
}

type KubeControllerService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// CIDR Range for Pods in cluster
	ClusterCIDR string `yaml:"cluster_cidr" json:"clusterCidr,omitempty"`
	// Virtual IP range that will be used by Kubernetes services
	ServiceClusterIPRange string `yaml:"service_cluster_ip_range" json:"serviceClusterIpRange,omitempty"`
}

type KubeletService struct {
	// Base service properties
	BaseService `yaml:",inline" json:",inline"`
	// Domain of the cluster (default: "cluster.local")
	ClusterDomain string `yaml:"cluster_domain" json:"clusterDomain,omitempty"`
	// The image whose network/ipc namespaces containers in each pod will use
	InfraContainerImage string `yaml:"infra_container_image" json:"infraContainerImage,omitempty"`
	// Cluster DNS service ip
	ClusterDNSServer string `yaml:"cluster_dns_server" json:"clusterDnsServer,omitempty"`
	// Fail if swap is enabled
	FailSwapOn bool `yaml:"fail_swap_on" json:"failSwapOn,omitempty"`
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
	Image string `yaml:"image" json:"image,omitempty"`
	// Extra arguments that are added to the services
	ExtraArgs map[string]string `yaml:"extra_args" json:"extraArgs,omitempty"`
	// Extra binds added to the nodes
	ExtraBinds []string `yaml:"extra_binds" json:"extraBinds,omitempty"`
}

type NetworkConfig struct {
	// Network Plugin That will be used in kubernetes cluster
	Plugin string `yaml:"plugin" json:"plugin,omitempty"`
	// Plugin options to configure network properties
	Options map[string]string `yaml:"options" json:"options,omitempty"`
	// YunionNetworkProvider
	YunionNetworkProvider *YunionNetworkProvider `yaml:",omitempty" json:"yunionNetworkProvider,omitempty"`
}

type AuthnConfig struct {
	// Authentication strategy that will be used in kubernetes cluster
	Strategy string `yaml:"strategy" json:"strategy,omitempty"`
	// Authentication options
	Options map[string]string `yaml:"options" json:"options,omitempty"`
	// List of additional hostnames and IPs to include in the api server PKI cert
	SANs []string `yaml:"sans" json:"sans,omitempty"`
}

type AuthzConfig struct {
	// Authorization mode used by kubernetes
	Mode string `yaml:"mode" json:"mode,omitempty"`
	// Authorization mode options
	Options map[string]string `yaml:"options" json:"options,omitempty"`
}

type IngressConfig struct {
	// Ingress controller type used by kubernetes
	Provider string `yaml:"provider" json:"provider,omitempty"`
	// Ingress controller options
	Options map[string]string `yaml:"options" json:"options,omitempty"`
	// NodeSelector key pair
	NodeSelector map[string]string `yaml:"node_selector" json:"nodeSelector,omitempty"`
}

type Plan struct {
	// List of node Plans
	Nodes []ConfigNodePlan `json:"nodes,omitempty"`
}

type File struct {
	Name     string `json:"name,omitempty"`
	Contents string `json:"contents,omitempty"`
}

type ConfigNodePlan struct {
	// Node address
	Address string `json:"address,omitempty"`
	// map of named processes that should run on the node
	Processes map[string]Process `json:"processes,omitempty"`
	// List of portchecks that should be open on the node
	PortChecks []PortCheck `json:"portChecks,omitempty"`
	// List of files to deploy on the node
	Files []File `json:"files,omitempty"`
	// Node Annotations
	Annotations map[string]string `json:"annotations,omitempty"`
	// Node Labels
	Labels map[string]string `json:"labels,omitempty"`
}

type Process struct {
	// Process name, this should be the container name
	Name string `json:"name,omitempty"`
	// Process Entrypoint command
	Command []string `json:"command,omitempty"`
	// Process args
	Args []string `json:"args,omitempty"`
	// Environment variables list
	Env []string `json:"env,omitempty"`
	// Process docker image
	Image string `json:"image,omitempty"`
	//AuthConfig for image private registry
	ImageRegistryAuthConfig string `json:"imageRegistryAuthConfig,omitempty"`
	// Process docker image VolumesFrom
	VolumesFrom []string `json:"volumesFrom,omitempty"`
	// Process docker container bind mounts
	Binds []string `json:"binds,omitempty"`
	// Process docker container netwotk mode
	NetworkMode string `json:"networkMode,omitempty"`
	// Process container restart policy
	RestartPolicy string `json:"restartPolicy,omitempty"`
	// Process container pid mode
	PidMode string `json:"pidMode,omitempty"`
	// Run process in privileged container
	Privileged bool `json:"privileged,omitempty"`
	// Process healthcheck
	HealthCheck HealthCheck `json:"healthCheck,omitempty"`
}

type HealthCheck struct {
	// Healthcheck URL
	URL string `json:"url,omitempty"`
}

type PortCheck struct {
	// Portcheck address to check.
	Address string `json:"address,omitempty"`
	// Port number
	Port int `json:"port,omitempty"`
	// Port Protocol
	Protocol string `json:"protocol,omitempty"`
}

type CloudProvider struct {
	// Name of the Cloud Provider
	Name string `yaml:"name" json:"name,omitempty"`
	// Configuration Options of Cloud Provider
	CloudConfig map[string]string `yaml:"cloud_config" json:"cloudConfig,omitempty"`
}

type YunionNetworkProvider struct {
}
