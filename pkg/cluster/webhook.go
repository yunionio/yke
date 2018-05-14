package cluster

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	WebhookConfigDeployer = "webhook-config-deployer"
	WebhookConfigPath     = "/etc/kubernetes/webhook.kubeconfig"
	WebhookServiceName    = "webhook"
	WebhookConfigEnv      = "YKE_WEBHOOK_CONFIG"
)

func deployWebhookConfig(ctx context.Context, uniqueHosts []*hosts.Host, alpineImage string, webhookConfig string, prsMap map[string]types.PrivateRegistry) error {
	for _, host := range uniqueHosts {
		log.Infof("[%s] Deploying webhook config file to node [%s]", WebhookServiceName, host.Address)
		if err := doDeployWebhookConfigFile(ctx, host, webhookConfig, alpineImage, prsMap); err != nil {
			return fmt.Errorf("Failed to deploy webhook config file on node [%s]: %v", host.Address, err)
		}
	}
	return nil
}

func doDeployWebhookConfigFile(ctx context.Context, host *hosts.Host, webhookConfig string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	// remove existing container. Only way it's still here is if previous deployment failed
	if err := docker.DoRemoveContainer(ctx, host.DClient, WebhookConfigDeployer, host.Address); err != nil {
		return err
	}
	containerEnv := []string{WebhookConfigEnv + "=" + webhookConfig}
	imageCfg := &container.Config{
		Image: alpineImage,
		Cmd: []string{
			"sh",
			"-c",
			fmt.Sprintf("if [ ! -f %s ]; then echo -e \"$%s\" > %s;fi", WebhookConfigPath, WebhookConfigEnv, WebhookConfigPath),
		},
		Env: containerEnv,
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			"/etc/kubernetes:/etc/kubernetes",
		},
		Privileged: true,
	}
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, WebhookConfigDeployer, host.Address, WebhookServiceName, prsMap); err != nil {
		return err
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, WebhookConfigDeployer, host.Address); err != nil {
		return err
	}
	log.Debugf("[%s] Successfully started cloud config deployer container on node [%s]", WebhookConfigDeployer, host.Address)
	return nil
}
