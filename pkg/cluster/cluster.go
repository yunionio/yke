package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"

	"yunion.io/yke/pkg/authz"
	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/services"
	"yunion.io/yke/pkg/templates"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	X509AuthenticationProvider = "x509"
	StateConfigMapName         = "cluster-state"
	UpdateStateTimeout         = 30
	GetStateTimeout            = 30
	KubernetesClientTimeOut    = 30
	NoneAuthorizationMode      = "none"
	LocalNodeAddress           = "127.0.0.1"
	LocalNodeHostname          = "localhost"
	LocalNodeUser              = "root"
	CloudProvider              = "CloudProvider"
)

type Cluster struct {
	types.KubernetesEngineConfig  `yaml:",inline"`
	ConfigPath                    string
	LocalKubeConfigPath           string
	LocalKubeYunionUserConfigPath string
	EtcdHosts                     []*hosts.Host
	WorkerHosts                   []*hosts.Host
	ControlPlaneHosts             []*hosts.Host
	InactiveHosts                 []*hosts.Host
	KubeClient                    *kubernetes.Clientset
	KubernetesServiceIP           net.IP
	Certificates                  map[string]pki.CertificatePKI
	ClusterDomain                 string
	ClusterCIDR                   string
	ClusterDNSServer              string
	DockerDialerFactory           tunnel.DialerFactory
	LocalConnDialerFactory        tunnel.DialerFactory
	PrivateRegistriesMap          map[string]types.PrivateRegistry
	K8sWrapTransport              k8s.WrapTransport
	UseKubectlDeploy              bool
	UpdateWorkersOnly             bool
	CloudConfigFile               string
	WebhookConfig                 string
}

func ParseConfig(clusterFile string) (*types.KubernetesEngineConfig, error) {
	log.Debugf("Parsing cluster file [%v]", clusterFile)
	var config types.KubernetesEngineConfig
	if err := yaml.Unmarshal([]byte(clusterFile), &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func ParseCluster(
	ctx context.Context,
	engineConfig *types.KubernetesEngineConfig,
	clusterFilePath, configDir string,
	dockerDialerFactory, localConnDialerFactory tunnel.DialerFactory,
	k8sWrapTransport k8s.WrapTransport,
) (*Cluster, error) {
	var err error
	c := &Cluster{
		KubernetesEngineConfig: *engineConfig,
		ConfigPath:             clusterFilePath,
		DockerDialerFactory:    dockerDialerFactory,
		LocalConnDialerFactory: localConnDialerFactory,
		PrivateRegistriesMap:   make(map[string]types.PrivateRegistry),
		K8sWrapTransport:       k8sWrapTransport,
	}
	// Setting cluster Defaults
	c.setClusterDefaults(ctx)

	if err := c.InvertIndexHosts(); err != nil {
		return nil, fmt.Errorf("Failed to classify hosts from config file: %v", err)
	}

	// parse WebhookConfig
	if err := c.parseWebhookConfig(ctx); err != nil {
		return nil, fmt.Errorf("Failed to parse webhook config: %v", err)
	}

	if err := c.ValidateCluster(); err != nil {
		return nil, fmt.Errorf("Failed to validate cluster: %v", err)
	}
	c.KubernetesServiceIP, err = pki.GetKubernetesServiceIP(c.Services.KubeAPI.ServiceClusterIPRange)
	if err != nil {
		return nil, fmt.Errorf("Failed to get Kubernetes Service IP: %v", err)
	}
	c.ClusterDomain = c.Services.Kubelet.ClusterDomain
	c.ClusterCIDR = c.Services.KubeController.ClusterCIDR
	c.ClusterDNSServer = c.Services.Kubelet.ClusterDNSServer
	if len(c.ConfigPath) == 0 {
		c.ConfigPath = pki.ClusterConfig
	}
	c.LocalKubeConfigPath = pki.GetLocalKubeConfig(c.ConfigPath, configDir)
	c.LocalKubeYunionUserConfigPath = pki.GetLocalYunionKubeConfig(c.ConfigPath, configDir)

	for _, pr := range c.PrivateRegistries {
		if pr.URL == "" {
			pr.URL = docker.DockerRegistryURL
		}
		c.PrivateRegistriesMap[pr.URL] = pr
	}
	// parse the cluster config file
	c.CloudConfigFile, err = c.parseCloudConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse cloud config file: %v", err)
	}

	return c, nil
}

func rebuildLocalAdminConfig(ctx context.Context, kubeCluster *Cluster) error {
	if len(kubeCluster.ControlPlaneHosts) == 0 {
		return nil
	}
	log.Infof("[reconcile] Rebuilding and updating local kube config")
	var workingConfig, newConfig string
	currentKubeConfig := kubeCluster.Certificates[pki.KubeAdminCertName]
	caCrt := kubeCluster.Certificates[pki.CACertName].Certificate
	for _, cpHost := range kubeCluster.ControlPlaneHosts {
		if (currentKubeConfig == pki.CertificatePKI{}) {
			kubeCluster.Certificates = make(map[string]pki.CertificatePKI)
			newConfig = getLocalAdminConfigWithNewAddress(kubeCluster.LocalKubeConfigPath, cpHost.Address, kubeCluster.ClusterName)
		} else {
			kubeURL := fmt.Sprintf("https://%s:6443", cpHost.Address)
			caData := string(cert.EncodeCertPEM(caCrt))
			crtData := string(cert.EncodeCertPEM(currentKubeConfig.Certificate))
			keyData := string(cert.EncodePrivateKeyPEM(currentKubeConfig.Key))
			newConfig = pki.GetKubeConfigX509WithData(kubeURL, kubeCluster.ClusterName, pki.KubeAdminCertName, caData, crtData, keyData)
		}
		if err := pki.DeployAdminConfig(ctx, newConfig, kubeCluster.LocalKubeConfigPath); err != nil {
			return fmt.Errorf("Failed to redeploy local admin config with new host")
		}
		workingConfig = newConfig
		if _, err := GetK8sVersion(kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport); err == nil {
			log.Infof("[reconcile] host [%s] is active master on the cluster", cpHost.Address)
			break
		}
	}
	currentKubeConfig.Config = workingConfig
	kubeCluster.Certificates[pki.KubeAdminCertName] = currentKubeConfig
	return nil
}

func (c *Cluster) parseCloudConfig(ctx context.Context) (string, error) {
	if len(c.CloudProvider.CloudConfig) == 0 {
		return "", nil
	}
	// handle generic cloud config
	tmpMap := make(map[string]interface{})
	for key, value := range c.CloudProvider.CloudConfig {
		tmpBool, err := strconv.ParseBool(value)
		if err == nil {
			tmpMap[key] = tmpBool
			continue
		}
		tmpInt, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			tmpMap[key] = tmpInt
			continue
		}
		tmpFloat, err := strconv.ParseFloat(value, 64)
		if err == nil {
			tmpMap[key] = tmpFloat
			continue
		}
		tmpMap[key] = value
	}
	jsonString, err := json.MarshalIndent(tmpMap, "", "\n")
	if err != nil {
		return "", err
	}
	return string(jsonString), nil
}

func (c *Cluster) parseWebhookConfig(ctx context.Context) error {
	if c.WebhookAuth.URL == "" {
		return nil
	}

	config, err := templates.CompileTemplateFromMap(templates.WebhookAuthTemplate, map[string]string{
		"URL": c.WebhookAuth.URL,
	})
	if err != nil {
		return fmt.Errorf("Generate webhook auth config error: %v", err)
	}
	c.WebhookConfig = config
	return nil
}

func isLocalConfigWorking(ctx context.Context, localKubeConfigPath string, k8sWrapTransport k8s.WrapTransport) bool {
	if _, err := GetK8sVersion(localKubeConfigPath, k8sWrapTransport); err != nil {
		log.Infof("[reconcile] Local config is not vaild, rebuilding admin config")
		return false
	}
	return true
}

func getLocalConfigAddress(localConfigPath string) (string, error) {
	config, err := clientcmd.BuildConfigFromFlags("", localConfigPath)
	if err != nil {
		return "", err
	}
	splittedAdress := strings.Split(config.Host, ":")
	address := splittedAdress[1]
	return address[2:], nil
}

func getLocalAdminConfigWithNewAddress(localConfigPath, cpAddress string, clusterName string) string {
	config, _ := clientcmd.BuildConfigFromFlags("", localConfigPath)
	if config == nil {
		return ""
	}
	config.Host = fmt.Sprintf("https://%s:6443", cpAddress)
	return pki.GetKubeConfigX509WithData(
		"https://"+cpAddress+":6443",
		clusterName,
		pki.KubeAdminCertName,
		string(config.CAData),
		string(config.CertData),
		string(config.KeyData))
}

func ApplyAuthzResources(ctx context.Context, config types.KubernetesEngineConfig, clusterFilePath, configDir string, k8sWrapTransport k8s.WrapTransport) error {
	// dialer factories are not needed here since we are not uses docker only k8s jobs
	kubeCluster, err := ParseCluster(ctx, &config, clusterFilePath, configDir, nil, nil, k8sWrapTransport)
	if err != nil {
		return err
	}
	if len(kubeCluster.ControlPlaneHosts) == 0 {
		return nil
	}
	if err := authz.ApplyJobDeployerServiceAccount(ctx, kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport); err != nil {
		return fmt.Errorf("Failed to apply the ServiceAccount needed for job execution: %v", err)
	}
	if kubeCluster.Authorization.Mode == NoneAuthorizationMode {
		return nil
	}
	if kubeCluster.Authorization.Mode == services.RBACAuthorizationMode {
		if err := authz.ApplySystemNodeClusterRoleBinding(ctx, kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport); err != nil {
			return fmt.Errorf("Failed to apply the ClusterRoleBinding needed for node authorization: %v", err)
		}
	}
	if kubeCluster.Authorization.Mode == services.RBACAuthorizationMode && kubeCluster.Services.KubeAPI.PodSecurityPolicy {
		if err := authz.ApplyDefaultPodSecurityPolicy(ctx, kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport); err != nil {
			return fmt.Errorf("Failed to apply default PodSecurityPolicy: %v", err)
		}
		if err := authz.ApplyDefaultPodSecurityPolicyRole(ctx, kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport); err != nil {
			return fmt.Errorf("Failed to apply default PodSecurityPolicy ClusterRole and ClusterRoleBinding: %v", err)
		}
	}
	return nil
}

func (c *Cluster) SyncLabelsAndTaints(ctx context.Context) error {
	if len(c.ControlPlaneHosts) > 0 {
		log.Infof("[sync] Syncing nodes Labels and Taints")
		k8sClient, err := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
		if err != nil {
			return fmt.Errorf("Failed to initialize new kubernetes client: %v", err)
		}
		for _, host := range hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts) {
			if err := k8s.SetAddressesAnnotations(k8sClient, host.HostnameOverride, host.InternalAddress, host.Address); err != nil {
				return err
			}
			if err := k8s.SyncLabels(k8sClient, host.HostnameOverride, host.ToAddLabels, host.ToDelLabels); err != nil {
				return err
			}
			// Taints are not being added by user
			if err := k8s.SyncTaints(k8sClient, host.HostnameOverride, host.ToAddTaints, host.ToDelTaints); err != nil {
				return err
			}
		}
		log.Infof("[sync] Successfully synced nodes Labels and Taints")
	}
	return nil
}

func (c *Cluster) getEtcdProcessHostMap(readyEtcdHosts []*hosts.Host) map[*hosts.Host]types.Process {
	etcdProcessHostMap := make(map[*hosts.Host]types.Process)
	for _, host := range c.EtcdHosts {
		if !host.ToAddEtcdMember {
			etcdProcessHostMap[host] = c.BuildEtcdProcess(host, readyEtcdHosts)
		}
	}
	return etcdProcessHostMap
}

func (c *Cluster) PrePullK8sImages(ctx context.Context) error {
	log.Infof("Pre-pulling kubernetes images")
	var errgrp errgroup.Group
	hosts := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
	for _, host := range hosts {
		//if !host.UpdateWorker {
		//continue
		//}
		runHost := host
		errgrp.Go(func() error {
			return docker.UseLocalOrPull(ctx, runHost.DClient, runHost.Address, c.SystemImages.Kubernetes, "pre-deploy", c.PrivateRegistriesMap)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("Kubernetes images pulled successfully")
	return nil
}

func (c *Cluster) DeployControlPlane(ctx context.Context) error {
	// Deploy Etcd Plane
	etcdProcessHostMap := c.getEtcdProcessHostMap(nil)
	if len(c.Services.Etcd.ExternalURLs) > 0 {
		log.Infof("[etcd] External etcd connection string has been specified, skipping etcd plane")
	} else {
		if err := services.RunEtcdPlane(ctx, c.EtcdHosts, etcdProcessHostMap, c.LocalConnDialerFactory, c.PrivateRegistriesMap, c.UpdateWorkersOnly, c.SystemImages.Alpine); err != nil {
			return fmt.Errorf("[etcd] Failed to bring up Etcd Plane: %v", err)
		}
	}

	// Deploy Control plane
	processMap := map[string]types.Process{
		services.SidekickContainerName:       c.BuildSidecarProcess(),
		services.KubeAPIContainerName:        c.BuildKubeAPIProcess(),
		services.KubeControllerContainerName: c.BuildKubeControllerProcess(),
		services.SchedulerContainerName:      c.BuildSchedulerProcess(),
		services.YunionWebhookContainerName:  c.BuildYunionWebhookProcess(),
	}
	if err := services.RunControlPlane(ctx, c.ControlPlaneHosts,
		c.LocalConnDialerFactory,
		c.PrivateRegistriesMap,
		processMap,
		c.UpdateWorkersOnly,
		c.SystemImages.Alpine); err != nil {
		return fmt.Errorf("[controlPlane] Failed to bring up Control Plane: %v", err)
	}

	return nil
}

func (c *Cluster) DeployWorkerPlane(ctx context.Context) error {
	// Deploy Worker Plane
	processMap := map[string]types.Process{
		services.SidekickContainerName:   c.BuildSidecarProcess(),
		services.KubeproxyContainerName:  c.BuildKubeProxyProcess(),
		services.NginxProxyContainerName: c.BuildProxyProcess(),
	}
	kubeletProcessHostMap := make(map[*hosts.Host]types.Process)
	for _, host := range hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts) {
		kubeletProcessHostMap[host] = c.BuildKubeletProcess(host)
	}
	allHosts := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
	if err := services.RunWorkerPlane(ctx, allHosts,
		c.LocalConnDialerFactory,
		c.PrivateRegistriesMap,
		processMap,
		kubeletProcessHostMap,
		c.Certificates,
		c.UpdateWorkersOnly,
		c.SystemImages.Alpine); err != nil {
		return fmt.Errorf("[workerPlane] Failed to bring up Worker Plane: %v", err)
	}
	return nil
}

func (c *Cluster) AllHosts() []*hosts.Host {
	return hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
}

func (c *Cluster) ConfigureCluster(
	ctx context.Context,
	clusterFilePath, configDir string,
	k8sWrapTransport k8s.WrapTransport,
	useKubectl bool) error {
	c.UseKubectlDeploy = useKubectl
	if len(c.ControlPlaneHosts) > 0 {
		if err := c.deployNetworkPlugin(ctx); err != nil {
			return err
		}
		return c.deployAddons(ctx)
	}
	return nil
}

func (c *Cluster) deployAddons(ctx context.Context) error {
	if err := c.deployK8sAddOns(ctx); err != nil {
		return err
	}
	return c.deployUserAddOns(ctx)
}
