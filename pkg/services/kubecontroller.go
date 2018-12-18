package services

import (
	"context"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/types"
)

func runKubeController(ctx context.Context, host *hosts.Host, df hosts.DialerFactory, prsMap map[string]types.PrivateRegistry, controllerProcess types.Process, alpineImage string) error {
	imageCfg, hostCfg, healthCheckURL := GetProcessConfig(controllerProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, KubeControllerContainerName, host.Address, ControlRole, prsMap); err != nil {
		return err
	}
	if err := runHealthcheck(ctx, host, KubeControllerContainerName, df, healthCheckURL, nil); err != nil {
		return err
	}
	return createLogLink(ctx, host, KubeControllerContainerName, ControlRole, alpineImage, prsMap)
}

func removeKubeController(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, KubeControllerContainerName, host.Address)
}

func restartKubeController(ctx context.Context, host *hosts.Host) error {
	return docker.DoRestartContainer(ctx, host.DClient, KubeControllerContainerName, host.Address)
}
