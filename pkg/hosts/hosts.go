package hosts

import (
	"context"
	"fmt"

	dtypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"yunion.io/yke/pkg/docker"
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
	UpdateWork          bool
}

func (h *Host) TunnelHostConfig() tunnel.HostConfig {
	return tunnel.HostConfig{
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
