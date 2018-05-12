package cluster

import (
	"context"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v2"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

func (c *Cluster) SaveClusterState(ctx context.Context, config *types.KubernetesEngineConfig) error {
	if len(c.ControlPlaneHosts) > 0 {
		// Reinitialize kubernetes Client
		var err error
		c.KubeClient, err = k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
		if err != nil {
			return fmt.Errorf("Failed to re-initialize Kubernetes Client: %v", err)
		}
		err = saveClusterCerts(ctx, c.KubeClient, c.Certificates)
		if err != nil {
			return fmt.Errorf("[certificates] Failed to Save Kubernetes certificates: %v", err)
		}
		err = saveStateToKubernetes(ctx, c.KubeClient, c.LocalKubeConfigPath, config)
		if err != nil {
			return fmt.Errorf("[state] Failed to save configuration state: %v", err)
		}
	}
	return nil
}

func (c *Cluster) GetClusterState(ctx context.Context) (*Cluster, error) {
	var err error
	var currentCluster *Cluster

	// check if local kubeconfig file exists
	if _, err = os.Stat(c.LocalKubeConfigPath); !os.IsNotExist(err) {
		log.Infof("[state] Found local kube config file, trying to get state from cluster")

		// to handle if current local admin is down and we need to use new cp from the list
		if !isLocalConfigWorking(ctx, c.LocalKubeConfigPath, c.K8sWrapTransport) {
			if err := rebuildLocalAdminConfig(ctx, c); err != nil {
				return nil, err
			}
		}

		// initiate kubernetes client
		c.KubeClient, err = k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
		if err != nil {
			log.Warningf("Failed to initiate new Kubernetes Client: %v", err)
			return nil, nil
		}
		// Get previous kubernetes state
		currentCluster = getStateFromKubernetes(ctx, c.KubeClient, c.LocalKubeConfigPath)
		// Get previous kubernetes certificates
		if currentCluster != nil {
			if err := currentCluster.InvertIndexHosts(); err != nil {
				return nil, fmt.Errorf("Failed to classify hosts from fetched cluster: %v", err)
			}
			currentCluster.Certificates, err = getClusterCerts(ctx, c.KubeClient, currentCluster.EtcdHosts)
			currentCluster.DockerDialerFactory = c.DockerDialerFactory
			currentCluster.LocalConnDialerFactory = c.LocalConnDialerFactory
			if err != nil {
				return nil, fmt.Errorf("Failed to Get Kubernetes certificates: %v", err)
			}
			// setting cluster defaults for the fetched cluster as well
			currentCluster.setClusterDefaults(ctx)

			currentCluster.Certificates, err = regenerateAPICertificate(c, currentCluster.Certificates)
			if err != nil {
				return nil, fmt.Errorf("Failed to regenerate KubeAPI certificate %v", err)
			}
		}
	}
	return currentCluster, nil
}

func saveStateToKubernetes(ctx context.Context, kubeClient *kubernetes.Clientset, kubeConfigPath string, config *types.KubernetesEngineConfig) error {
	log.Infof("[state] Saving cluster state to Kubernetes")
	clusterFile, err := yaml.Marshal(*config)
	if err != nil {
		return err
	}
	timeout := make(chan bool, 1)
	go func() {
		for {
			err := k8s.UpdateConfigMap(kubeClient, clusterFile, StateConfigMapName)
			if err != nil {
				time.Sleep(time.Second * 5)
				continue
			}
			log.Infof("[state] Successfully Saved cluster state to Kubernetes ConfigMap: %s", StateConfigMapName)
			timeout <- true
			break
		}
	}()
	select {
	case <-timeout:
		return nil
	case <-time.After(time.Second * UpdateStateTimeout):
		return fmt.Errorf("[state] Timeout waiting for kubernetes to be ready")
	}
}

func getStateFromKubernetes(ctx context.Context, kubeClient *kubernetes.Clientset, kubeConfigPath string) *Cluster {
	log.Infof("[state] Fetching cluster state from Kubernetes")
	var cfgMap *v1.ConfigMap
	var currentCluster Cluster
	var err error
	timeout := make(chan bool, 1)
	go func() {
		for {
			cfgMap, err = k8s.GetConfigMap(kubeClient, StateConfigMapName)
			if err != nil {
				time.Sleep(time.Second * 5)
				continue
			}
			log.Infof("[state] Successfully Fetched cluster state to Kubernetes ConfigMap: %s", StateConfigMapName)
			timeout <- true
			break
		}
	}()
	select {
	case <-timeout:
		clusterData := cfgMap.Data[StateConfigMapName]
		err := yaml.Unmarshal([]byte(clusterData), &currentCluster)
		if err != nil {
			return nil
		}
		return &currentCluster
	case <-time.After(time.Second * GetStateTimeout):
		log.Infof("Timed out waiting for kubernetes cluster to get state")
		return nil
	}
}

func GetK8sVersion(localConfigPath string, k8sWrapTransport k8s.WrapTransport) (string, error) {
	log.Debugf("[version] Using %s to connect to Kubernetes cluster..", localConfigPath)
	k8sClient, err := k8s.NewClient(localConfigPath, k8sWrapTransport)
	if err != nil {
		return "", fmt.Errorf("Failed to create Kubernetes Client: %v", err)
	}
	discoveryClient := k8sClient.DiscoveryClient
	log.Debugf("[version] Getting Kubernetes server version..")
	serverVersion, err := discoveryClient.ServerVersion()
	if err != nil {
		return "", fmt.Errorf("Failed to get Kubernetes server version: %v", err)
	}
	return fmt.Sprintf("%#v", *serverVersion), nil
}
