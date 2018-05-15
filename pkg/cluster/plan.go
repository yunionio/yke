package cluster

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	b64 "encoding/base64"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/services"
	"yunion.io/yke/pkg/types"
)

const (
	EtcdPathPrefix = "/registry"
)

func GeneratePlan(ctx context.Context, config *types.KubernetesEngineConfig) (types.Plan, error) {
	clusterPlan := types.Plan{}
	myCluster, _ := ParseCluster(ctx, config, "", "", nil, nil, nil)
	// rkeConfig.Nodes are already unique. But they don't have role flags. So I will use the parsed cluster.Hosts to make use of the role flags.
	uniqHosts := hosts.GetUniqueHostList(myCluster.EtcdHosts, myCluster.ControlPlaneHosts, myCluster.WorkerHosts)
	for _, host := range uniqHosts {
		clusterPlan.Nodes = append(clusterPlan.Nodes, BuildKEConfigNodePlan(ctx, myCluster, host))
	}
	return clusterPlan, nil
}

func BuildKEConfigNodePlan(ctx context.Context, myCluster *Cluster, host *hosts.Host) types.ConfigNodePlan {
	processes := map[string]types.Process{}
	portChecks := []types.PortCheck{}
	// Everybody gets a sidecar and a kubelet..
	processes[services.SidekickContainerName] = myCluster.BuildSidecarProcess()
	processes[services.KubeletContainerName] = myCluster.BuildKubeletProcess(host)
	processes[services.KubeproxyContainerName] = myCluster.BuildKubeProxyProcess()

	portChecks = append(portChecks, BuildPortChecksFromPortList(host, WorkerPortList, ProtocolTCP)...)
	// Do we need an nginxProxy for this one ?
	if host.IsWorker && !host.IsControl {
		processes[services.NginxProxyContainerName] = myCluster.BuildProxyProcess()
	}
	if host.IsControl {
		processes[services.KubeAPIContainerName] = myCluster.BuildKubeAPIProcess()
		processes[services.KubeControllerContainerName] = myCluster.BuildKubeControllerProcess()
		processes[services.SchedulerContainerName] = myCluster.BuildSchedulerProcess()

		portChecks = append(portChecks, BuildPortChecksFromPortList(host, ControlPlanePortList, ProtocolTCP)...)
	}
	if host.IsEtcd {
		processes[services.EtcdContainerName] = myCluster.BuildEtcdProcess(host, nil)

		portChecks = append(portChecks, BuildPortChecksFromPortList(host, EtcdPortList, ProtocolTCP)...)
	}
	cloudConfig := types.File{
		Name:     CloudConfigPath,
		Contents: b64.StdEncoding.EncodeToString([]byte(myCluster.CloudConfigFile)),
	}
	return types.ConfigNodePlan{
		Address:    host.Address,
		Processes:  processes,
		PortChecks: portChecks,
		Files:      []types.File{cloudConfig},
		Annotations: map[string]string{
			k8s.ExternalAddressAnnotation: host.Address,
			k8s.InternalAddressAnnotation: host.InternalAddress,
		},
		Labels: host.ToAddLabels,
	}
}

func (c *Cluster) BuildKubeAPIProcess() types.Process {
	// check if external etcd is used
	etcdConnectionString := services.GetEtcdConnString(c.EtcdHosts)
	etcdPathPrefix := EtcdPathPrefix
	etcdClientCert := pki.GetCertPath(pki.KubeNodeCertName)
	etcdClientKey := pki.GetKeyPath(pki.KubeNodeCertName)
	etcdCAClientCert := pki.GetCertPath(pki.CACertName)
	if len(c.Services.Etcd.ExternalURLs) > 0 {
		etcdConnectionString = strings.Join(c.Services.Etcd.ExternalURLs, ",")
		etcdPathPrefix = c.Services.Etcd.Path
		etcdClientCert = pki.GetCertPath(pki.EtcdClientCertName)
		etcdClientKey = pki.GetKeyPath(pki.EtcdClientCertName)
		etcdCAClientCert = pki.GetCertPath(pki.EtcdClientCACertName)
	}

	Command := []string{
		"/opt/rke/entrypoint.sh",
		"kube-apiserver",
	}

	CommandArgs := map[string]string{
		"insecure-bind-address":           "127.0.0.1",
		"bind-address":                    "0.0.0.0",
		"insecure-port":                   "0",
		"secure-port":                     "6443",
		"cloud-provider":                  c.CloudProvider.Name,
		"allow-privileged":                "true",
		"kubelet-preferred-address-types": "InternalIP,ExternalIP,Hostname",
		"service-cluster-ip-range":        c.Services.KubeAPI.ServiceClusterIPRange,
		"admission-control":               "ServiceAccount,NamespaceLifecycle,LimitRanger,PersistentVolumeLabel,DefaultStorageClass,ResourceQuota,DefaultTolerationSeconds",
		"storage-backend":                 "etcd3",
		"client-ca-file":                  pki.GetCertPath(pki.CACertName),
		"tls-cert-file":                   pki.GetCertPath(pki.KubeAPICertName),
		"tls-private-key-file":            pki.GetKeyPath(pki.KubeAPICertName),
		"kubelet-client-certificate":      pki.GetCertPath(pki.KubeAPICertName),
		"kubelet-client-key":              pki.GetKeyPath(pki.KubeAPICertName),
		"service-account-key-file":        pki.GetKeyPath(pki.KubeAPICertName),
	}
	if len(c.CloudProvider.Name) > 0 {
		CommandArgs["cloud-config"] = CloudConfigPath
	}
	args := []string{
		"--etcd-cafile=" + etcdCAClientCert,
		"--etcd-certfile=" + etcdClientCert,
		"--etcd-keyfile=" + etcdClientKey,
		"--etcd-servers=" + etcdConnectionString,
		"--etcd-prefix=" + etcdPathPrefix,
	}

	if c.Authorization.Mode == services.RBACAuthorizationMode {
		CommandArgs["authorization-mode"] = "Node,RBAC"
	}
	if c.Services.KubeAPI.PodSecurityPolicy {
		CommandArgs["runtime-config"] = "extensions/v1beta1/podsecuritypolicy=true"
		CommandArgs["admission-control"] = CommandArgs["admission-control"] + ",PodSecurityPolicy"
	}

	VolumesFrom := []string{
		services.SidekickContainerName,
	}
	Binds := []string{
		"/etc/kubernetes:/etc/kubernetes:z",
	}

	// Override args if they exist, add additional args
	for arg, value := range c.Services.KubeAPI.ExtraArgs {
		if _, ok := c.Services.KubeAPI.ExtraArgs[arg]; ok {
			CommandArgs[arg] = value
		}
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s=%s", arg, value)
		Command = append(Command, cmd)
	}

	Binds = append(Binds, c.Services.KubeAPI.ExtraBinds...)

	healthCheck := types.HealthCheck{
		URL: services.GetHealthCheckURL(true, services.KubeAPIPort),
	}
	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.Services.KubeAPI.Image, c.PrivateRegistriesMap)

	return types.Process{
		Name:                    services.KubeAPIContainerName,
		Command:                 Command,
		Args:                    args,
		VolumesFrom:             VolumesFrom,
		Binds:                   Binds,
		NetworkMode:             "host",
		RestartPolicy:           "always",
		Image:                   c.Services.KubeAPI.Image,
		HealthCheck:             healthCheck,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildKubeControllerProcess() types.Process {
	Command := []string{
		"/opt/rke/entrypoint.sh",
		"kube-controller-manager",
	}

	CommandArgs := map[string]string{
		"address":                     "0.0.0.0",
		"cloud-provider":              c.CloudProvider.Name,
		"allow-untagged-cloud":        "true",
		"configure-cloud-routes":      "false",
		"leader-elect":                "true",
		"kubeconfig":                  pki.GetConfigPath(pki.KubeControllerCertName),
		"enable-hostpath-provisioner": "false",
		"node-monitor-grace-period":   "40s",
		"pod-eviction-timeout":        "5m0s",
		"v": "2",
		"allocate-node-cidrs":              "true",
		"cluster-cidr":                     c.ClusterCIDR,
		"service-cluster-ip-range":         c.Services.KubeController.ServiceClusterIPRange,
		"service-account-private-key-file": pki.GetKeyPath(pki.KubeAPICertName),
		"root-ca-file":                     pki.GetCertPath(pki.CACertName),
	}
	if len(c.CloudProvider.Name) > 0 {
		CommandArgs["cloud-config"] = CloudConfigPath
	}
	args := []string{}
	if c.Authorization.Mode == services.RBACAuthorizationMode {
		args = append(args, "--use-service-account-credentials=true")
	}
	VolumesFrom := []string{
		services.SidekickContainerName,
	}
	Binds := []string{
		"/etc/kubernetes:/etc/kubernetes:z",
	}

	for arg, value := range c.Services.KubeController.ExtraArgs {
		if _, ok := c.Services.KubeController.ExtraArgs[arg]; ok {
			CommandArgs[arg] = value
		}
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s=%s", arg, value)
		Command = append(Command, cmd)
	}

	Binds = append(Binds, c.Services.KubeController.ExtraBinds...)

	healthCheck := types.HealthCheck{
		URL: services.GetHealthCheckURL(false, services.KubeControllerPort),
	}

	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.Services.KubeController.Image, c.PrivateRegistriesMap)
	return types.Process{
		Name:                    services.KubeControllerContainerName,
		Command:                 Command,
		Args:                    args,
		VolumesFrom:             VolumesFrom,
		Binds:                   Binds,
		NetworkMode:             "host",
		RestartPolicy:           "always",
		Image:                   c.Services.KubeController.Image,
		HealthCheck:             healthCheck,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildKubeletProcess(host *hosts.Host) types.Process {

	Command := []string{
		"/opt/rke/entrypoint.sh",
		"kubelet",
	}

	CommandArgs := map[string]string{
		"v":                         "2",
		"address":                   "0.0.0.0",
		"cadvisor-port":             "0",
		"read-only-port":            "0",
		"cluster-domain":            c.ClusterDomain,
		"pod-infra-container-image": c.Services.Kubelet.InfraContainerImage,
		"cgroups-per-qos":           "True",
		"enforce-node-allocatable":  "",
		"hostname-override":         host.HostnameOverride,
		"cluster-dns":               c.ClusterDNSServer,
		"network-plugin":            "cni",
		"cni-conf-dir":              "/etc/cni/net.d",
		"cni-bin-dir":               "/opt/cni/bin",
		"resolv-conf":               "/etc/resolv.conf",
		"allow-privileged":          "true",
		"cloud-provider":            c.CloudProvider.Name,
		"kubeconfig":                pki.GetConfigPath(pki.KubeNodeCertName),
		"client-ca-file":            pki.GetCertPath(pki.CACertName),
		"anonymous-auth":            "false",
		"volume-plugin-dir":         "/var/lib/kubelet/volumeplugins",
		"fail-swap-on":              strconv.FormatBool(c.Services.Kubelet.FailSwapOn),
	}
	if host.Address != host.InternalAddress {
		CommandArgs["node-ip"] = host.InternalAddress
	}
	if len(c.CloudProvider.Name) > 0 {
		CommandArgs["cloud-config"] = CloudConfigPath
	}
	VolumesFrom := []string{
		services.SidekickContainerName,
	}
	Binds := []string{
		"/etc/kubernetes:/etc/kubernetes:z",
		"/etc/cni:/etc/cni:ro,z",
		"/opt/cni:/opt/cni:ro,z",
		"/var/lib/cni:/var/lib/cni:z",
		"/etc/resolv.conf:/etc/resolv.conf",
		"/sys:/sys:rprivate",
		host.DockerInfo.DockerRootDir + ":" + host.DockerInfo.DockerRootDir + ":rw,rprivate,z",
		"/var/lib/kubelet:/var/lib/kubelet:shared,z",
		"/var/run:/var/run:rw,rprivate",
		"/run:/run:rprivate",
		"/etc/ceph:/etc/ceph",
		"/dev:/host/dev:rprivate",
		"/var/log/containers:/var/log/containers:z",
		"/var/log/pods:/var/log/pods:z",
		"/opt/cloud/workspace/servers/hostinfo:/opt/cloud/workspace/servers/hostinfo:ro",
		"/lib/modules:/lib/modules:z",
		"/usr/bin/ovs-vsctl:/usr/bin/ovs-vsctl",
		"/usr/bin/ovs-ofctl:/usr/bin/ovs-ofctl",
	}

	for arg, value := range c.Services.Kubelet.ExtraArgs {
		if _, ok := c.Services.Kubelet.ExtraArgs[arg]; ok {
			CommandArgs[arg] = value
		}
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s=%s", arg, value)
		Command = append(Command, cmd)
	}

	Binds = append(Binds, c.Services.Kubelet.ExtraBinds...)

	healthCheck := types.HealthCheck{
		URL: services.GetHealthCheckURL(true, services.KubeletPort),
	}
	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.Services.Kubelet.Image, c.PrivateRegistriesMap)

	return types.Process{
		Name:                    services.KubeletContainerName,
		Command:                 Command,
		VolumesFrom:             VolumesFrom,
		Binds:                   Binds,
		NetworkMode:             "host",
		RestartPolicy:           "always",
		Image:                   c.Services.Kubelet.Image,
		PidMode:                 "host",
		Privileged:              true,
		HealthCheck:             healthCheck,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildKubeProxyProcess() types.Process {
	Command := []string{
		"/opt/rke/entrypoint.sh",
		"kube-proxy",
	}

	CommandArgs := map[string]string{
		"v": "2",
		"healthz-bind-address": "0.0.0.0",
		"kubeconfig":           pki.GetConfigPath(pki.KubeProxyCertName),
	}

	VolumesFrom := []string{
		services.SidekickContainerName,
	}
	Binds := []string{
		"/etc/kubernetes:/etc/kubernetes:z",
	}

	for arg, value := range c.Services.Kubeproxy.ExtraArgs {
		if _, ok := c.Services.Kubeproxy.ExtraArgs[arg]; ok {
			CommandArgs[arg] = value
		}
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s=%s", arg, value)
		Command = append(Command, cmd)
	}

	Binds = append(Binds, c.Services.Kubeproxy.ExtraBinds...)

	healthCheck := types.HealthCheck{
		URL: services.GetHealthCheckURL(false, services.KubeproxyPort),
	}
	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.Services.Kubeproxy.Image, c.PrivateRegistriesMap)
	return types.Process{
		Name:          services.KubeproxyContainerName,
		Command:       Command,
		VolumesFrom:   VolumesFrom,
		Binds:         Binds,
		NetworkMode:   "host",
		RestartPolicy: "always",
		PidMode:       "host",
		Privileged:    true,
		HealthCheck:   healthCheck,
		Image:         c.Services.Kubeproxy.Image,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildProxyProcess() types.Process {
	nginxProxyEnv := ""
	for i, host := range c.ControlPlaneHosts {
		nginxProxyEnv += fmt.Sprintf("%s", host.InternalAddress)
		if i < (len(c.ControlPlaneHosts) - 1) {
			nginxProxyEnv += ","
		}
	}
	Env := []string{fmt.Sprintf("%s=%s", services.NginxProxyEnvName, nginxProxyEnv)}

	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.SystemImages.NginxProxy, c.PrivateRegistriesMap)
	return types.Process{
		Name:          services.NginxProxyContainerName,
		Env:           Env,
		Args:          Env,
		NetworkMode:   "host",
		RestartPolicy: "always",
		HealthCheck:   types.HealthCheck{},
		Image:         c.SystemImages.NginxProxy,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildSchedulerProcess() types.Process {
	Command := []string{
		"/opt/rke/entrypoint.sh",
		"kube-scheduler",
	}

	CommandArgs := map[string]string{
		"leader-elect": "true",
		"v":            "2",
		"address":      "0.0.0.0",
		"kubeconfig":   pki.GetConfigPath(pki.KubeSchedulerCertName),
	}

	VolumesFrom := []string{
		services.SidekickContainerName,
	}
	Binds := []string{
		"/etc/kubernetes:/etc/kubernetes:z",
	}

	for arg, value := range c.Services.Scheduler.ExtraArgs {
		if _, ok := c.Services.Scheduler.ExtraArgs[arg]; ok {
			CommandArgs[arg] = value
		}
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s=%s", arg, value)
		Command = append(Command, cmd)
	}

	Binds = append(Binds, c.Services.Scheduler.ExtraBinds...)

	healthCheck := types.HealthCheck{
		URL: services.GetHealthCheckURL(false, services.SchedulerPort),
	}
	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.Services.Scheduler.Image, c.PrivateRegistriesMap)
	return types.Process{
		Name:                    services.SchedulerContainerName,
		Command:                 Command,
		Binds:                   Binds,
		VolumesFrom:             VolumesFrom,
		NetworkMode:             "host",
		RestartPolicy:           "always",
		Image:                   c.Services.Scheduler.Image,
		HealthCheck:             healthCheck,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildSidecarProcess() types.Process {
	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.SystemImages.KubernetesServicesSidecar, c.PrivateRegistriesMap)
	return types.Process{
		Name:                    services.SidekickContainerName,
		NetworkMode:             "none",
		Image:                   c.SystemImages.KubernetesServicesSidecar,
		HealthCheck:             types.HealthCheck{},
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildEtcdProcess(host *hosts.Host, etcdHosts []*hosts.Host) types.Process {
	nodeName := pki.GetEtcdCrtName(host.InternalAddress)
	initCluster := ""
	if len(etcdHosts) == 0 {
		initCluster = services.GetEtcdInitialCluster(c.EtcdHosts)
	} else {
		initCluster = services.GetEtcdInitialCluster(etcdHosts)
	}

	clusterState := "new"
	if host.ExistingEtcdCluster {
		clusterState = "existing"
	}
	args := []string{
		"/usr/local/bin/etcd",
		"--peer-client-cert-auth",
		"--client-cert-auth",
	}

	CommandArgs := map[string]string{
		"name":                        "etcd-" + host.HostnameOverride,
		"data-dir":                    "/var/lib/rancher/etcd",
		"advertise-client-urls":       "https://" + host.InternalAddress + ":2379,https://" + host.InternalAddress + ":4001",
		"listen-client-urls":          "https://0.0.0.0:2379",
		"initial-advertise-peer-urls": "https://" + host.InternalAddress + ":2380",
		"listen-peer-urls":            "https://0.0.0.0:2380",
		"initial-cluster-token":       "etcd-cluster-1",
		"initial-cluster":             initCluster,
		"initial-cluster-state":       clusterState,
		"trusted-ca-file":             pki.GetCertPath(pki.CACertName),
		"peer-trusted-ca-file":        pki.GetCertPath(pki.CACertName),
		"cert-file":                   pki.GetCertPath(nodeName),
		"key-file":                    pki.GetKeyPath(nodeName),
		"peer-cert-file":              pki.GetCertPath(nodeName),
		"peer-key-file":               pki.GetKeyPath(nodeName),
	}

	Binds := []string{
		"/var/lib/etcd:/var/lib/rancher/etcd:z",
		"/etc/kubernetes:/etc/kubernetes:z",
	}

	for arg, value := range c.Services.Etcd.ExtraArgs {
		if _, ok := c.Services.Etcd.ExtraArgs[arg]; ok {
			CommandArgs[arg] = value
		}
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s=%s", arg, value)
		args = append(args, cmd)
	}

	Binds = append(Binds, c.Services.Etcd.ExtraBinds...)

	healthCheck := types.HealthCheck{
		URL: services.EtcdHealthCheckURL,
	}
	registryAuthConfig, _, _ := docker.GetImageRegistryConfig(c.Services.Etcd.Image, c.PrivateRegistriesMap)

	return types.Process{
		Name:                    services.EtcdContainerName,
		Args:                    args,
		Binds:                   Binds,
		NetworkMode:             "host",
		RestartPolicy:           "always",
		Image:                   c.Services.Etcd.Image,
		HealthCheck:             healthCheck,
		ImageRegistryAuthConfig: registryAuthConfig,
	}
}

func (c *Cluster) BuildYunionWebhookProcess() types.Process {
	s := c.Services.YunionWebhookAuth
	Command := []string{
		"/k8s-keystone-auth",
		"--debug",
	}

	CommandArgs := map[string]string{
		"kube-config":     "/etc/kubernetes/kube_config_cluster.yml",
		"os-auth-url":     s.OsAuthURL,
		"os-username":     s.OsUsername,
		"os-password":     s.OsPassword,
		"os-project-name": s.OsProjectName,
		"os-region-name":  s.OsRegionName,
	}

	for arg, value := range CommandArgs {
		cmd := fmt.Sprintf("--%s", arg)
		Command = append(Command, cmd, value)
	}

	VolumesFrom := []string{
		services.SidekickContainerName,
	}

	Binds := []string{
		"/etc/kubernetes:/etc/kubernetes:z",
	}

	return types.Process{
		Name:          services.YunionWebhookContainerName,
		Command:       Command,
		VolumesFrom:   VolumesFrom,
		Binds:         Binds,
		NetworkMode:   "host",
		RestartPolicy: "always",
		Image:         c.Services.YunionWebhookAuth.Image,
	}
}

func BuildPortChecksFromPortList(host *hosts.Host, portList []string, proto string) []types.PortCheck {
	portChecks := []types.PortCheck{}
	for _, port := range portList {
		intPort, _ := strconv.Atoi(port)
		portChecks = append(portChecks, types.PortCheck{
			Address:  host.Address,
			Port:     intPort,
			Protocol: proto,
		})
	}
	return portChecks
}
