package services

import (
	"context"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/types"
)

func runKubelet(ctx context.Context, host *hosts.Host, df hosts.DialerFactory, prsMap map[string]types.PrivateRegistry, kubeletProcess types.Process, certMap map[string]pki.CertificatePKI, alpineImage string) error {
	imageCfg, hostCfg, healthCheckURL := GetProcessConfig(kubeletProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, KubeletContainerName, host.Address, WorkerRole, prsMap); err != nil {
		return err
	}
	if err := runHealthcheck(ctx, host, KubeletContainerName, df, healthCheckURL, certMap); err != nil {
		return err
	}
	return createLogLink(ctx, host, KubeletContainerName, WorkerRole, alpineImage, prsMap)
}

func removeKubelet(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, KubeletContainerName, host.Address)
}

func restartKubelet(ctx context.Context, host *hosts.Host) error {
	return docker.DoRestartContainer(ctx, host.DClient, KubeletContainerName, host.Address)
}
