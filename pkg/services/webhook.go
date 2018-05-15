package services

import (
	"context"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yke/pkg/types"
)

func runYunionWebhook(ctx context.Context, host *hosts.Host, df tunnel.DialerFactory, prsMap map[string]types.PrivateRegistry, webhookProcess types.Process, alpineImage string) error {
	imageCfg, hostCfg, _ := GetProcessConfig(webhookProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, YunionWebhookContainerName, host.Address, ControlRole, prsMap); err != nil {
		return err
	}
	return createLogLink(ctx, host, YunionWebhookContainerName, ControlRole, alpineImage, prsMap)
}

func removeYunionWebhook(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, YunionWebhookContainerName, host.Address)
}
