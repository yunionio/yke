package cluster

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v2"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/authz"
	"yunion.io/x/yke/pkg/cloudprovider"
	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/k8s"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/services"
	"yunion.io/x/yke/pkg/templates"
	"yunion.io/x/yke/pkg/types"
	"yunion.io/x/yke/pkg/util"
)

type Cluster struct {
	types.KubernetesEngineConfig `yaml:",inline"`
	ConfigPath                   string
	LocalKubeConfigPath          string
	EtcdHosts                    []*hosts.Host
	WorkerHosts                  []*hosts.Host
	ControlPlaneHosts            []*hosts.Host
	InactiveHosts                []*hosts.Host
	EtcdReadyHosts               []*hosts.Host
	KubeClient                   *kubernetes.Clientset
	KubernetesServiceIP          net.IP
	Certificates                 map[string]pki.CertificatePKI
	ClusterDomain                string
	ClusterCIDR                  string
	ClusterDNSServer             string
	DockerDialerFactory          hosts.DialerFactory
	LocalConnDialerFactory       hosts.DialerFactory
	PrivateRegistriesMap         map[string]types.PrivateRegistry
	K8sWrapTransport             k8s.WrapTransport
	UseKubectlDeploy             bool
	UpdateWorkersOnly            bool
	CloudConfigFile              string
	WebhookConfig                string
	SchedulerPolicyConfig        string
}

const (
	X509AuthenticationProvider = "x509"
	StateConfigMapName         = "cluster-state"
	UpdateStateTimeout         = 30
	GetStateTimeout            = 30
	KubernetesClientTimeOut    = 30
	SyncWorkers                = 10
	NoneAuthorizationMode      = "none"
	LocalNodeAddress           = "127.0.0.1"
	LocalNodeHostname          = "localhost"
	LocalNodeUser              = "root"
	CloudProvider              = "CloudProvider"
	ControlPlane               = "controlPlane"
	WorkerPlane                = "workerPlan"
	EtcdPlane                  = "etcd"

	KubeAppLabel = "k8s-app"
	AppLabel     = "app"
	NameLabel    = "name"

	WorkerThreads = util.WorkerThreads
)

func (c *Cluster) DeployControlPlane(ctx context.Context) error {
	// Deploy Etcd Plane
	etcdNodePlanMap := make(map[string]types.ConfigNodePlan)
	// Build etcd node plan map
	for _, etcdHost := range c.EtcdHosts {
		etcdNodePlanMap[etcdHost.Address] = BuildKEConfigNodePlan(ctx, c, etcdHost, etcdHost.DockerInfo)
	}

	if len(c.Services.Etcd.ExternalURLs) > 0 {
		log.Infof("[etcd] External etcd connection string has been specified, skipping etcd plane")
	} else {
		etcdRollingSnapshot := services.EtcdSnapshot{
			Snapshot:  c.Services.Etcd.Snapshot,
			Creation:  c.Services.Etcd.Creation,
			Retention: c.Services.Etcd.Retention,
		}
		if err := services.RunEtcdPlane(ctx, c.EtcdHosts, etcdNodePlanMap, c.LocalConnDialerFactory, c.PrivateRegistriesMap, c.UpdateWorkersOnly, c.SystemImages.Alpine, etcdRollingSnapshot); err != nil {
			return fmt.Errorf("[etcd] Failed to bring up Etcd Plane: %v", err)
		}
	}

	// Deploy Control plane
	cpNodePlanMap := make(map[string]types.ConfigNodePlan)
	// buld cp node plan map
	for _, cpHost := range c.ControlPlaneHosts {
		cpNodePlanMap[cpHost.Address] = BuildKEConfigNodePlan(ctx, c, cpHost, cpHost.DockerInfo)
	}
	if err := services.RunControlPlane(ctx, c.ControlPlaneHosts,
		c.LocalConnDialerFactory,
		c.PrivateRegistriesMap,
		cpNodePlanMap,
		c.UpdateWorkersOnly,
		c.SystemImages.Alpine,
		c.Certificates); err != nil {
		return fmt.Errorf("[controlPlane] Failed to bring up Control Plane: %v", err)
	}

	return nil
}

func (c *Cluster) DeployWorkerPlane(ctx context.Context) error {
	// Deploy Worker Plane
	workerNodePlanMap := make(map[string]types.ConfigNodePlan)
	// Build cp node plan map
	allHosts := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
	for _, workerHost := range allHosts {
		workerNodePlanMap[workerHost.Address] = BuildKEConfigNodePlan(ctx, c, workerHost, workerHost.DockerInfo)
	}
	if err := services.RunWorkerPlane(ctx, allHosts,
		c.LocalConnDialerFactory,
		c.PrivateRegistriesMap,
		workerNodePlanMap,
		c.Certificates,
		c.UpdateWorkersOnly,
		c.SystemImages.Alpine); err != nil {
		return fmt.Errorf("[workerPlane] Failed to bring up Worker Plane: %v", err)
	}
	return nil
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
	dockerDialerFactory, localConnDialerFactory hosts.DialerFactory,
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

	// parse SchedulerPolicyConfig
	if err := c.parseSchedulerConfig(ctx); err != nil {
		return nil, fmt.Errorf("Failed to parse scheduler config: %v", err)
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

	for _, pr := range c.PrivateRegistries {
		if pr.URL == "" {
			pr.URL = docker.DockerRegistryURL
		}
		c.PrivateRegistriesMap[pr.URL] = pr
	}

	// Get Cloud Provider
	p, err := cloudprovider.InitCloudProvider(c.CloudProvider)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize cloud provider: %v", err)
	}
	if p != nil {
		c.CloudConfigFile, err = p.GenerateCloudConfigFile()
		if err != nil {
			return nil, fmt.Errorf("Failed to parse cloud config file: %v", err)
		}
		c.CloudProvider.Name = p.GetName()
		if c.CloudProvider.Name == "" {
			return nil, fmt.Errorf("Name of the cloud provider is not defined for custom provider")
		}
	}

	// Create k8s wrap transport for bastion host
	if len(c.BastionHost.Address) > 0 {
		var err error
		c.K8sWrapTransport, err = hosts.BastionHostWrapTransport(c.BastionHost)
		if err != nil {
			return nil, err
		}
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
			return fmt.Errorf("Failed to redeploy local admin config with new host: %v", err)
		}
		if err := deployAdminConfig(ctx, kubeCluster.AllHosts(), newConfig, kubeCluster.SystemImages.Alpine, kubeCluster.PrivateRegistriesMap); err != nil {
			return fmt.Errorf("Failed to redeploy admin config to remote host: %v", err)
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

func (c *Cluster) deployAddons(ctx context.Context) error {
	if err := c.deployK8sAddOns(ctx); err != nil {
		return err
	}
	if err := c.deployUserAddOns(ctx); err != nil {
		if err, ok := err.(*addonError); ok && err.isCritical {
			return err
		}
		log.Warningf("Failed to deploy addon execute job [%s]: %v", UserAddonsIncludeResourceName, err)
	}
	return nil
}

func (c *Cluster) SyncLabelsAndTaints(ctx context.Context, currentCluster *Cluster) error {
	// Handle issue when deleting all controlplane nodes https://github.com/rancher/rancher/issues/15810
	if currentCluster != nil {
		cpToDelete := hosts.GetToDeleteHosts(currentCluster.ControlPlaneHosts, c.ControlPlaneHosts, c.InactiveHosts)
		if len(cpToDelete) == len(currentCluster.ControlPlaneHosts) {
			log.Infof("[sync] Cleaning left control plane nodes from reconcilation")
			for _, toDeleteHost := range cpToDelete {
				if err := cleanControlNode(ctx, c, currentCluster, toDeleteHost); err != nil {
					return err
				}
			}
		}
	}
	if len(c.ControlPlaneHosts) > 0 {
		log.Infof("[sync] Syncing nodes Labels and Taints")
		k8sClient, err := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
		if err != nil {
			return fmt.Errorf("Failed to initialize new kubernetes client: %v", err)
		}
		hostList := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
		var errgrp errgroup.Group
		hostQueue := make(chan *hosts.Host, len(hostList))
		for _, host := range hostList {
			hostQueue <- host
		}
		close(hostQueue)

		for i := 0; i < SyncWorkers; i++ {
			w := i
			errgrp.Go(func() error {
				var errs []error
				for host := range hostQueue {
					log.Debugf("worker [%d] starting sync for node [%d]", w, host.HostnameOverride)
					if err := setNodeAnnotationsLabelsTaints(k8sClient, host); err != nil {
						errs = append(errs, err)
					}
				}
				if len(errs) > 0 {
					return fmt.Errorf("%v", errs)
				}
				return nil
			})
		}
		if err := errgrp.Wait(); err != nil {
			return err
		}
		log.Infof("[sync] Successfully synced nodes Labels and Taints")
	}
	return nil
}

func setNodeAnnotationsLabelsTaints(k8sClient *kubernetes.Clientset, host *hosts.Host) error {
	node := &v1.Node{}
	var err error
	for retries := 0; retries <= 5; retries++ {
		node, err = k8s.GetNode(k8sClient, host.HostnameOverride)
		if err != nil {
			log.Debugf("[hosts] Can't find node by name [%s], retrying..", host.HostnameOverride)
			time.Sleep(2 * time.Second)
			continue
		}

		oldNode := node.DeepCopy()
		k8s.SetNodeAddressesAnnotations(node, host.InternalAddress, host.Address)
		k8s.SyncNodeLabels(node, host.ToAddLabels, host.ToDelLabels)
		k8s.SyncNodeTaints(node, host.ToAddTaints, host.ToDelTaints)

		if reflect.DeepEqual(oldNode, node) {
			log.Debugf("skipping syncing labels for node [%s]", node.Name)
			return nil
		}
		_, err = k8sClient.CoreV1().Nodes().Update(node)
		if err != nil {
			log.Debugf("Error syncing labels for node [%s]: %v", node.Name, err)
			time.Sleep(5 * time.Second)
			continue
		}
		return nil
	}
	return err
}

func (c *Cluster) PrePullK8sImages(ctx context.Context) error {
	log.Infof("Pre-pulling kubernetes images")
	var errgrp errgroup.Group
	hostList := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
	hostsQueue := util.GetObjectQueue(hostList)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				err := docker.UseLocalOrPull(ctx, runHost.DClient, runHost.Address, c.SystemImages.Kubernetes, "pre-deploy", c.PrivateRegistriesMap)
				if err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
		})
	}

	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("Kubernetes images pulled successfully")
	return nil
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

func (c *Cluster) AllHosts() []*hosts.Host {
	return hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
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

func (c *Cluster) parseSchedulerConfig(ctx context.Context) error {
	if c.YunionConfig.SchedulerUrl == "" {
		return nil
	}
	ret, err := url.Parse(c.YunionConfig.SchedulerUrl)
	if err != nil {
		return err
	}
	enableHTTPS := false
	if ret.Scheme == "https" {
		enableHTTPS = true
	}
	config, err := templates.CompileTemplateFromMap(templates.SchedulerPolicyConfigTemplate, map[string]interface{}{
		"SchedulerUrl": c.YunionConfig.SchedulerUrl,
		"EnableHTTPS":  enableHTTPS,
	})
	if err != nil {
		return fmt.Errorf("Generate scheduler policy config error: %v", err)
	}
	c.SchedulerPolicyConfig = config
	return nil
}

func RestartClusterPods(ctx context.Context, kubeCluster *Cluster) error {
	log.Infof("Restarting network, ingress, and metrics pods")
	// this will remove the pods created by RKE and let the controller creates them again
	kubeClient, err := k8s.NewClient(kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport)
	if err != nil {
		return fmt.Errorf("Failed to initialize new kubernetes client: %v", err)
	}
	// TODO: our app
	labelsList := []string{
		fmt.Sprintf("%s=%s", KubeAppLabel, fmt.Sprintf("%s-cni", YunionNetworkPlugin)),
		//fmt.Sprintf("%s=%s", KubeAppLabel, FlannelNetworkPlugin),
		//fmt.Sprintf("%s=%s", KubeAppLabel, CanalNetworkPlugin),
		//fmt.Sprintf("%s=%s", NameLabel, WeaveNetworkPlugin),
		fmt.Sprintf("%s=%s", AppLabel, NginxIngressAddonAppName),
		fmt.Sprintf("%s=%s", KubeAppLabel, DefaultMonitoringProvider),
		fmt.Sprintf("%s=%s", KubeAppLabel, KubeDNSAddonAppName),
		fmt.Sprintf("%s=%s", KubeAppLabel, KubeDNSAutoscalerAppName),
	}
	var errgrp errgroup.Group
	labelQueue := util.GetObjectQueue(labelsList)
	for w := 0; w < services.WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for label := range labelQueue {
				runLabel := label.(string)
				// list pods to be deleted
				pods, err := k8s.ListPodsByLabel(kubeClient, runLabel)
				if err != nil {
					errList = append(errList, err)
				}
				// delete pods
				err = k8s.DeletePods(kubeClient, pods)
				if err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
	}
	return nil
}
