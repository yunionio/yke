package services

import (
	"context"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/types"
)

func runKubeproxy(ctx context.Context, host *hosts.Host, df hosts.DialerFactory, prsMap map[string]types.PrivateRegistry, kubeProxyProcess types.Process, alpineImage string) error {
	imageCfg, hostCfg, healthCheckURL := GetProcessConfig(kubeProxyProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, KubeproxyContainerName, host.Address, WorkerRole, prsMap); err != nil {
		return err
	}
	if err := runHealthcheck(ctx, host, KubeproxyContainerName, df, healthCheckURL, nil); err != nil {
		return err
	}
	return createLogLink(ctx, host, KubeproxyContainerName, WorkerRole, alpineImage, prsMap)
}

func removeKubeproxy(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, KubeproxyContainerName, host.Address)
}

func restartKubeproxy(ctx context.Context, host *hosts.Host) error {
	return docker.DoRestartContainer(ctx, host.DClient, KubeproxyContainerName, host.Address)
}
