package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"golang.org/x/sync/errgroup"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/services"
	ytypes "yunion.io/x/yke/pkg/types"
	"yunion.io/x/yke/pkg/util"
)

const (
	etcdRoleLabel         = "node-role.kubernetes.io/etcd"
	controlplaneRoleLabel = "node-role.kubernetes.io/controlplane"
	workerRoleLabel       = "node-role.kubernetes.io/worker"
)

func (c *Cluster) TunnelHosts(ctx context.Context, local bool) error {
	if local {
		if err := c.ControlPlaneHosts[0].TunnelUpLocal(ctx, c.Version); err != nil {
			return fmt.Errorf("Failed to connect to docker for local host [%s]: %v", c.EtcdHosts[0].Address, err)
		}
		return nil
	}
	c.InactiveHosts = make([]*hosts.Host, 0)
	uniqueHosts := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
	var errgrp errgroup.Group
	for _, uniqueHost := range uniqueHosts {
		runHost := uniqueHost
		errgrp.Go(func() error {
			if err := runHost.TunnelUp(ctx, c.DockerDialerFactory, c.PrefixPath, c.Version); err != nil {
				// Unsupported Docker version is NOT a connectivity problem that we can recover! So we bail out on it
				if strings.Contains(err.Error(), "Unsupported Docker version found") {
					return err
				}
				log.Warningf("Failed to set up SSH tunneling for host [%s]: %v", runHost.Address, err)
				c.InactiveHosts = append(c.InactiveHosts, runHost)
			}
			return nil
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
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
		if c.BastionHost.Address != "" {
			// Add the bastion host information to eash host object
			newHost.BastionHost = c.BastionHost
		}
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

func (c *Cluster) SetUpHosts(ctx context.Context, rotateCerts bool) error {
	if c.Authentication.Strategy == X509AuthenticationProvider {
		log.Infof("[certificates] Deploying kubernetes certificates to Cluster nodes")
		hostList := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)
		var errgrp errgroup.Group
		hostsQueue := util.GetObjectQueue(hostList)
		for w := 0; w < WorkerThreads; w++ {
			errgrp.Go(func() error {
				var errList []error
				for host := range hostsQueue {
					err := pki.DeployCertificatesOnPlaneHost(ctx, host.(*hosts.Host), c.KubernetesEngineConfig, c.Certificates, c.SystemImages.CertDownloader, c.PrivateRegistriesMap, rotateCerts)
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

		if err := pki.DeployAdminConfig(ctx, c.Certificates[pki.KubeAdminCertName].Config, c.LocalKubeConfigPath); err != nil {
			return err
		}
		if err := deployAdminConfig(ctx, hostList, c.Certificates[pki.KubeAdminCertName].Config, c.SystemImages.Alpine, c.PrivateRegistriesMap); err != nil {
			return err
		}
		if err := deployLogrotateConfig(ctx, hostList, c.YunionConfig.DockerGraphDir, c.SystemImages.Alpine, c.PrivateRegistriesMap); err != nil {
			return err
		}
		log.Infof("[certificates] Successfully deployed kubernetes certificates to Cluster nodes")
		if c.CloudProvider.Name != "" {
			if err := deployCloudProviderConfig(ctx, hostList, c.SystemImages.Alpine, c.PrivateRegistriesMap, c.CloudConfigFile); err != nil {
				return err
			}
			log.Infof("[%s] Successfully deployed kubernetes cloud config to Cluster nodes", CloudConfigServiceName)
		}
	}

	if c.WebhookConfig != "" {
		if err := deployWebhookConfig(ctx, c.ControlPlaneHosts, c.SystemImages.Alpine, c.WebhookConfig, c.PrivateRegistriesMap); err != nil {
			return err
		}
		log.Infof("[%s] Successfully deployed kubernetes webhook file to Cluster nodes", WebhookConfigDeployer)
	}
	if c.SchedulerPolicyConfig != "" {
		if err := deploySchedulerConfig(ctx, c.ControlPlaneHosts, c.SystemImages.Alpine, c.SchedulerPolicyConfig, c.PrivateRegistriesMap); err != nil {
			return err
		}
	}
	return nil
}

func CheckEtcdHostsChanged(kubeCluster, currentCluster *Cluster) error {
	if currentCluster != nil {
		etcdChanged := hosts.IsHostListChanged(currentCluster.EtcdHosts, kubeCluster.EtcdHosts)
		if etcdChanged {
			return fmt.Errorf("Adding or removing Etcd nodes is not supported")
		}
	}
	return nil
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
