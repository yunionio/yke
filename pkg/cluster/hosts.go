package cluster

import (
	"context"
	//"net"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"

	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/services"
	ytypes "yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	etcdRoleLabel         = "node-role.kubernetes.io/etcd"
	controlplaneRoleLabel = "node-role.kubernetes.io/controlplane"
	workerRoleLabel       = "node-role.kubernetes.io/worker"
)

func (c *Cluster) TunnelHosts(ctx context.Context, local bool) error {
	if local {
		if err := c.ControlPlaneHosts[0].TunnelUpLocal(ctx); err != nil {
			return fmt.Errorf("Failed to connect to docker for local host [%s]: %v", c.EtcdHosts[0].Address, err)
		}
		return nil
	}
	c.InactiveHosts = make([]*hosts.Host, 0)
	uniqueHosts := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
	for i := range uniqueHosts {
		if err := uniqueHosts[i].TunnelUp(ctx, c.DockerDialerFactory); err != nil {
			// Unsupported Docker version is NOT a connectivity problem that we can recover! So we bail out on it
			if strings.Contains(err.Error(), "Unsupported Docker version found") {
				return err
			}
			log.Warningf("Failed to set up SSH tunneling for host [%s]: %v", uniqueHosts[i].Address, err)
			c.InactiveHosts = append(c.InactiveHosts, uniqueHosts[i])
		}
	}
	for _, host := range c.InactiveHosts {
		log.Warningf("Removing host [%s] from node lists", host.Address)
		c.EtcdHosts = removeFromHosts(host, c.EtcdHosts)
		c.ControlPlaneHosts = removeFromHosts(host, c.ControlPlaneHosts)
		c.WorkerHosts = removeFromHosts(host, c.WorkerHosts)
		c.KubernetesEngineConfig.Nodes = removeFromKENodes(host.ConfigNode, c.KubernetesEngineConfig.Nodes)
	}
	return ValidateHostCount(c)
}

func removeFromHosts(hostToRemove *hosts.Host, hostList []*hosts.Host) []*hosts.Host {
	for i := range hostList {
		if hostToRemove.Address == hostList[i].Address {
			return append(hostList[:i], hostList[i+1:]...)
		}
	}
	return hostList
}

func removeFromKENodes(nodeToRemove ytypes.ConfigNode, nodeList []ytypes.ConfigNode) []ytypes.ConfigNode {
	for i := range nodeList {
		if nodeToRemove.Address == nodeList[i].Address {
			return append(nodeList[:i], nodeList[i+1:]...)
		}
	}
	return nodeList
}

func (c *Cluster) InvertIndexHosts() error {
	c.EtcdHosts = make([]*hosts.Host, 0)
	c.WorkerHosts = make([]*hosts.Host, 0)
	c.ControlPlaneHosts = make([]*hosts.Host, 0)
	for _, host := range c.Nodes {
		newHost := hosts.Host{
			ConfigNode:  host,
			ToAddLabels: map[string]string{},
			ToDelLabels: map[string]string{},
			ToAddTaints: []string{},
			ToDelTaints: []string{},
			DockerInfo: types.Info{
				DockerRootDir: "/var/lib/docker",
			},
		}
		for k, v := range host.Labels {
			newHost.ToAddLabels[k] = v
		}
		newHost.IgnoreDockerVersion = c.IgnoreDockerVersion

		for _, role := range host.Role {
			log.Debugf("Host: " + host.Address + " has role: " + role)
			switch role {
			case services.ETCDRole:
				newHost.IsEtcd = true
				newHost.ToAddLabels[etcdRoleLabel] = "true"
				c.EtcdHosts = append(c.EtcdHosts, &newHost)
			case services.ControlRole:
				newHost.IsControl = true
				newHost.ToAddLabels[controlplaneRoleLabel] = "true"
				c.ControlPlaneHosts = append(c.ControlPlaneHosts, &newHost)
			case services.WorkerRole:
				newHost.IsWorker = true
				newHost.ToAddLabels[workerRoleLabel] = "true"
				c.WorkerHosts = append(c.WorkerHosts, &newHost)
			default:
				return fmt.Errorf("Failed to recognize host [%s] role %s", host.Address, role)
			}
		}
		if !newHost.IsEtcd {
			newHost.ToDelLabels[etcdRoleLabel] = "true"
		}
		if !newHost.IsControl {
			newHost.ToDelLabels[controlplaneRoleLabel] = "true"
		}
		if !newHost.IsWorker {
			newHost.ToDelLabels[workerRoleLabel] = "true"
		}
	}
	return nil
}
