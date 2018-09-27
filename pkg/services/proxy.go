package services

import (
	"context"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/types"
)

const (
	NginxProxyImage   = "rancher/rke-nginx-proxy:0.1.0"
	NginxProxyEnvName = "CP_HOSTS"
)

func runNginxProxy(ctx context.Context, host *hosts.Host, prsMap map[string]types.PrivateRegistry, proxyProcess types.Process, alpineImage string) error {
	imageCfg, hostCfg, _ := GetProcessConfig(proxyProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, NginxProxyContainerName, host.Address, WorkerRole, prsMap); err != nil {
		return err
	}
	return createLogLink(ctx, host, NginxProxyContainerName, WorkerRole, alpineImage, prsMap)
}

func removeNginxProxy(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, NginxProxyContainerName, host.Address)
}
