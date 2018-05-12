package services

const (
	ETCDRole    = "etcd"
	ControlRole = "controlplane"
	WorkerRole  = "worker"

	SidekickServiceName   = "sidekick"
	RBACAuthorizationMode = "rbac"

	KubeAPIContainerName        = "kube-apiserver"
	KubeletContainerName        = "kubelet"
	KubeproxyContainerName      = "kube-proxy"
	KubeControllerContainerName = "kube-controller-manager"
	SchedulerContainerName      = "kube-scheduler"
	EtcdContainerName           = "etcd"
	NginxProxyContainerName     = "nginx-proxy"
	SidekickContainerName       = "service-sidekick"
	LogLinkContainerName        = "log-linker"
	LogCleanerContainerName     = "log-cleaner"

	KubeAPIPort        = 6443
	SchedulerPort      = 10251
	KubeControllerPort = 10252
	KubeletPort        = 10250
	KubeproxyPort      = 10256

	LogsPath = "/var/lib/yunion/rke/log"
)
