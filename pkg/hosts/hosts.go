package hosts

import (
	"context"
	"fmt"

	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	ToCleanEtcdDir       = "/var/lib/etcd"
	ToCleanSSLDir        = "/etc/kubernetes"
	ToCleanCNIConf       = "/etc/cni"
	ToCleanCNIBin        = "/opt/cni"
	ToCleanCNILib        = "/var/lib/cni"
	ToCleanTempCertPath  = "/etc/kubernetes/.tmp/"
	CleanerContainerName = "kube-cleaner"

	K8sVersion = "1.8"
)

type Host struct {
	types.ConfigNode
	DClient             *client.Client
	LocalConnPort       int
	IsControl           bool
	IsWorker            bool
	IsEtcd              bool
	IgnoreDockerVersion bool
	ToAddEtcdMember     bool
	ExistingEtcdCluster bool
	SavedKeyPhrase      string
	ToAddLabels         map[string]string
	ToDelLabels         map[string]string
	ToAddTaints         []string
	ToDelTaints         []string
	DockerInfo          dtypes.Info
	UpdateWorker        bool
}

func (h *Host) TunnelHostConfig() tunnel.HostConfig {
	return tunnel.HostConfig{
		NodeName:     h.NodeName,
		Address:      h.Address,
		Port:         h.Port,
		Username:     h.User,
		SSHKeyString: h.SSHKey,
		SSHKeyPath:   h.SSHKeyPath,
	}
}

func (h *Host) TunnelUp(ctx context.Context, dailerFactory tunnel.DialerFactory) error {
	var err error
	h.DClient, err = docker.TunnelUpClient(ctx, h.TunnelHostConfig(), dailerFactory)
	if err != nil {
		return err
	}
	return checkDockerVersion(ctx, h)
}

func (h *Host) TunnelUpLocal(ctx context.Context) error {
	var err error
	h.DClient, err = docker.TunnelUpLocalClient(ctx, h.TunnelHostConfig())
	if err != nil {
		return err
	}
	return checkDockerVersion(ctx, h)
}

func checkDockerVersion(ctx context.Context, h *Host) error {
	info, err := h.DClient.Info(ctx)
	if err != nil {
		return fmt.Errorf("Can't retrieve Docker Info: %v", err)
	}
	log.Debugf("Docker Info found: %#v", info)
	h.DockerInfo = info
	isvalid, err := docker.IsSupportedDockerVersion(info, K8sVersion)
	if err != nil {
		return fmt.Errorf("Error while determining supported Docker version [%s]: %v", info.ServerVersion, err)
	}

	if !isvalid && !h.IgnoreDockerVersion {
		return fmt.Errorf("Unsupported Docker version found [%s], supported versions are %v", info.ServerVersion, docker.K8sDockerVersions[K8sVersion])
	} else if !isvalid {
		log.Warningf("Unsupported Docker version found [%s], supported versions are %v", info.ServerVersion, docker.K8sDockerVersions[K8sVersion])
	}
	return nil
}

func (h *Host) CleanUpAll(ctx context.Context, cleanerImage string, prsMap map[string]types.PrivateRegistry, externalEtcd bool) error {
	log.Infof("[hosts] Cleaning up host [%s]", h.Address)
	toCleanPaths := []string{
		ToCleanSSLDir,
		ToCleanCNIConf,
		ToCleanCNIBin,
		ToCleanTempCertPath,
		ToCleanCNILib,
	}
	if !externalEtcd {
		toCleanPaths = append(toCleanPaths, ToCleanEtcdDir)
	}
	return h.CleanUp(ctx, toCleanPaths, cleanerImage, prsMap)
}

func (h *Host) CleanUpWorkerHost(ctx context.Context, cleanerImage string, prsMap map[string]types.PrivateRegistry) error {
	if h.IsControl || h.IsEtcd {
		log.Infof("[hosts] Host [%s] is already a controlplane or etcd host, skipping cleanup.", h.Address)
		return nil
	}
	toCleanPaths := []string{
		ToCleanSSLDir,
		ToCleanCNIConf,
		ToCleanCNIBin,
		ToCleanCNILib,
	}
	return h.CleanUp(ctx, toCleanPaths, cleanerImage, prsMap)
}

func (h *Host) CleanUpControlHost(ctx context.Context, cleanerImage string, prsMap map[string]types.PrivateRegistry) error {
	if h.IsWorker || h.IsEtcd {
		log.Infof("[hosts] Host [%s] is already a worker or etcd host, skipping cleanup.", h.Address)
		return nil
	}
	toCleanPaths := []string{
		ToCleanSSLDir,
		ToCleanCNIConf,
		ToCleanCNIBin,
		ToCleanCNILib,
	}
	return h.CleanUp(ctx, toCleanPaths, cleanerImage, prsMap)
}

func (h *Host) CleanUpEtcdHost(ctx context.Context, cleanerImage string, prsMap map[string]types.PrivateRegistry) error {
	toCleanPaths := []string{
		ToCleanEtcdDir,
		ToCleanSSLDir,
	}
	if h.IsWorker || h.IsControl {
		log.Infof("[hosts] Host [%s] is already a worker or control host, skipping cleanup certs.", h.Address)
		toCleanPaths = []string{
			ToCleanEtcdDir,
		}
	}
	return h.CleanUp(ctx, toCleanPaths, cleanerImage, prsMap)
}

func (h *Host) CleanUp(ctx context.Context, toCleanPaths []string, cleanerImage string, prsMap map[string]types.PrivateRegistry) error {
	log.Infof("[hosts] Cleaning up host [%s]", h.Address)
	imageCfg, hostCfg := buildCleanerConfig(h, toCleanPaths, cleanerImage)
	log.Infof("[hosts] Running cleaner container on host [%s]", h.Address)
	if err := docker.DoRunContainer(ctx, h.DClient, imageCfg, hostCfg, CleanerContainerName, h.Address, CleanerContainerName, prsMap); err != nil {
		return err
	}

	if err := docker.WaitForContainer(ctx, h.DClient, h.Address, CleanerContainerName); err != nil {
		return err
	}

	log.Infof("[hosts] Removing cleaner container on host [%s]", h.Address)
	if err := docker.RemoveContainer(ctx, h.DClient, h.Address, CleanerContainerName); err != nil {
		return err
	}
	log.Infof("[hosts] Successfully cleaned up host [%s]", h.Address)
	return nil
}

func DeleteNode(ctx context.Context, toDeleteHost *Host, kubeClient *kubernetes.Clientset, hasAnotherRole bool, cloudProvider string) error {
	if hasAnotherRole {
		log.Infof("[hosts] host [%s] has another role, skipping delete from kubernetes cluster", toDeleteHost.Address)
		return nil
	}
	log.Infof("[hosts] Cordoning host [%s]", toDeleteHost.Address)
	if _, err := k8s.GetNode(kubeClient, toDeleteHost.HostnameOverride); err != nil {
		if apierrors.IsNotFound(err) {
			log.Warningf("[hosts] Can't find node by name [%s]", toDeleteHost.Address)
			return nil
		}
		return err

	}
	if err := k8s.CordonUncordon(kubeClient, toDeleteHost.HostnameOverride, true); err != nil {
		return err
	}
	log.Infof("[hosts] Deleting host [%s] from the cluster", toDeleteHost.Address)
	if err := k8s.DeleteNode(kubeClient, toDeleteHost.HostnameOverride, cloudProvider); err != nil {
		return err
	}
	log.Infof("[hosts] Successfully deleted host [%s] from the cluster", toDeleteHost.Address)
	return nil
}

func NodesToHosts(cNodes []types.ConfigNode, nodeRole string) []*Host {
	hostList := make([]*Host, 0)
	for _, node := range cNodes {
		for _, role := range node.Role {
			if role == nodeRole {
				newHost := Host{
					ConfigNode: node,
				}
				hostList = append(hostList, &newHost)
				break
			}
		}
	}
	return hostList
}

func GetUniqueHostList(etcdHosts, cpHosts, workerHosts []*Host) []*Host {
	hostList := []*Host{}
	hostList = append(hostList, etcdHosts...)
	hostList = append(hostList, cpHosts...)
	hostList = append(hostList, workerHosts...)
	// little trick to get a unique host list
	uniqHostMap := make(map[*Host]bool)
	for _, host := range hostList {
		uniqHostMap[host] = true
	}
	uniqHostList := []*Host{}
	for host := range uniqHostMap {
		uniqHostList = append(uniqHostList, host)
	}
	return uniqHostList
}

func GetToDeleteHosts(currentHosts, configHosts, inactiveHosts []*Host) []*Host {
	toDeleteHosts := []*Host{}
	for _, currentHost := range currentHosts {
		found := false
		for _, newHost := range configHosts {
			if currentHost.Address == newHost.Address {
				found = true
			}
		}
		if !found {
			inactive := false
			for _, inactiveHost := range inactiveHosts {
				if inactiveHost.Address == currentHost.Address {
					inactive = true
					break
				}
			}
			if !inactive {
				toDeleteHosts = append(toDeleteHosts, currentHost)
			}
		}
	}
	return toDeleteHosts
}

func GetToAddHosts(currentHosts, configHosts []*Host) []*Host {
	toAddHosts := []*Host{}
	for _, configHost := range configHosts {
		found := false
		for _, currentHost := range currentHosts {
			if currentHost.Address == configHost.Address {
				found = true
				break
			}
		}
		if !found {
			toAddHosts = append(toAddHosts, configHost)
		}
	}
	return toAddHosts
}

func IsHostListChanged(currentHosts, configHosts []*Host) bool {
	changed := false
	for _, host := range currentHosts {
		found := false
		for _, configHost := range configHosts {
			if host.Address == configHost.Address {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	for _, host := range configHosts {
		found := false
		for _, currentHost := range currentHosts {
			if host.Address == currentHost.Address {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return changed
}

func buildCleanerConfig(host *Host, toCleanDirs []string, cleanerImage string) (*container.Config, *container.HostConfig) {
	cmd := append([]string{"rm", "-rf"}, toCleanDirs...)
	imageCfg := &container.Config{
		Image: cleanerImage,
		Cmd:   cmd,
	}
	bindMounts := []string{}
	for _, vol := range toCleanDirs {
		bindMounts = append(bindMounts, fmt.Sprintf("%s:%s:z", vol, vol))
	}
	hostCfg := &container.HostConfig{
		Binds: bindMounts,
	}
	return imageCfg, hostCfg
}
