package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	//"strings"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/cert"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/pki"
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
	types.KubernetesEngineConfig `yaml:",inline"`
	ConfigPath                   string
	LocalKubeConfigPath          string
	EtcdHosts                    []*hosts.Host
	WorkerHosts                  []*hosts.Host
	ControlPlaneHosts            []*hosts.Host
	InactiveHosts                []*hosts.Host
	KubeClient                   *kubernetes.Clientset
	KubernetesServiceIP          net.IP
	Certificates                 map[string]pki.CertificatePKI
	ClusterDomain                string
	ClusterCIDR                  string
	ClusterDNSServer             string
	DockerDialerFactory          tunnel.DialerFactory
	LocalConnDialerFactory       tunnel.DialerFactory
	PrivateRegistriesMap         map[string]types.PrivateRegistry
	K8sWrapTransport             k8s.WrapTransport
	UseKubectlDeploy             bool
	UpdateWorkersOnly            bool
	CloudConfigFile              string
	WebhookConfig                string
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
	// parse the cluster config file
	c.CloudConfigFile, err = c.parseCloudConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse cloud config file: %v", err)
	}

	// parse the cluster webhhok auth file
	c.WebhookConfig, err = c.parseWebhookConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse webhook config file: %v", err)
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

func (c *Cluster) parseWebhookConfig(ctx context.Context) (string, error) {
	if c.WebhookConfigFile == "" {
		return "", nil
	}

	bs, err := ioutil.ReadFile(c.WebhookConfigFile)
	if err != nil {
		return "", fmt.Errorf("Read WebhhokConfigFile error: %v", err)
	}
	return string(bs), nil
}

func isLocalConfigWorking(ctx context.Context, localKubeConfigPath string, k8sWrapTransport k8s.WrapTransport) bool {
	if _, err := GetK8sVersion(localKubeConfigPath, k8sWrapTransport); err != nil {
		log.Infof("[reconcile] Local config is not vaild, rebuilding admin config")
		return false
	}
	return true
}
