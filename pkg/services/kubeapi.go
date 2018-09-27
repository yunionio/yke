package services

import (
	"context"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/types"
)

func runKubeAPI(ctx context.Context, host *hosts.Host, df hosts.DialerFactory, prsMap map[string]types.PrivateRegistry, kubeAPIProcess types.Process, alpineImage string, certMap map[string]pki.CertificatePKI) error {
	imageCfg, hostCfg, healthCheckURL := GetProcessConfig(kubeAPIProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, KubeAPIContainerName, host.Address, ControlRole, prsMap); err != nil {
		return err
	}
	if err := runHealthcheck(ctx, host, KubeAPIContainerName, df, healthCheckURL, certMap); err != nil {
		return err
	}
	return createLogLink(ctx, host, KubeAPIContainerName, ControlRole, alpineImage, prsMap)
}

func removeKubeAPI(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, KubeAPIContainerName, host.Address)
}
