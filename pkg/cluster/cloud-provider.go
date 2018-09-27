package cluster

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/types"
)

const (
	CloudConfigDeployer    = "cloud-config-deployer"
	CloudConfigServiceName = "cloud"
	CloudConfigPath        = "/etc/kubernetes/cloud-config.json"
	CloudConfigEnv         = "YKE_CLOUD_CONFIG"
)

func deployCloudProviderConfig(ctx context.Context, uniqueHosts []*hosts.Host, alpineImage string, prsMap map[string]types.PrivateRegistry, cloudConfig string) error {
	for _, host := range uniqueHosts {
		log.Infof("[%s] Deploying cloud config file to node [%s]", CloudConfigServiceName, host.Address)
		if err := doDeployConfigFile(ctx, host, cloudConfig, alpineImage, prsMap); err != nil {
			return fmt.Errorf("Failed to deploy cloud config file on node [%s]: %v", host.Address, err)
		}
	}
	return nil
}

func doDeployConfigFile(ctx context.Context, host *hosts.Host, cloudConfig, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	// remove existing container. Only way it's still here is if previous deployment failed
	if err := docker.DoRemoveContainer(ctx, host.DClient, CloudConfigDeployer, host.Address); err != nil {
		return err
	}
	containerEnv := []string{CloudConfigEnv + "=" + cloudConfig}
	imageCfg := &container.Config{
		Image: alpineImage,
		Cmd: []string{
			"sh",
			"-c",
			fmt.Sprintf("t=$(mktemp); echo -e \"$%s\" > $t && mv $t %s && chmod 644 %s", CloudConfigEnv, CloudConfigPath, CloudConfigPath),
		},
		Env: containerEnv,
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			"/etc/kubernetes:/etc/kubernetes",
		},
		Privileged: true,
	}
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, CloudConfigDeployer, host.Address, CloudConfigServiceName, prsMap); err != nil {
		return err
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, CloudConfigDeployer, host.Address); err != nil {
		return err
	}
	log.Debugf("[%s] Successfully started cloud config deployer container on node [%s]", CloudConfigServiceName, host.Address)
	return nil
}
