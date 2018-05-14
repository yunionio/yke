package cluster

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"golang.org/x/sync/errgroup"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/services"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

func (c *Cluster) CleanDeadLogs(ctx context.Context) error {
	hosts := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)

	var errgrp errgroup.Group

	for _, host := range hosts {
		if !host.UpdateWorker {
			continue
		}
		runHost := host
		errgrp.Go(func() error {
			return doRunLogCleaner(ctx, runHost, c.SystemImages.Alpine, c.PrivateRegistriesMap)
		})
	}
	return errgrp.Wait()
}

func doRunLogCleaner(ctx context.Context, host *hosts.Host, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	log.Debugf("[cleanup] Starting log link cleanup on host [%s]", host.Address)
	imageCfg := &container.Config{
		Image: alpineImage,
		Tty:   true,
		Cmd: []string{
			"sh",
			"-c",
			fmt.Sprintf("find %s -type l ! -exec test -e {} \\; -print -delete", services.LogsPath),
		},
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			"/var/lib:/var/lib",
		},
		Privileged: true,
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, services.LogCleanerContainerName, host.Address); err != nil {
		return err
	}
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, services.LogCleanerContainerName, host.Address, "cleanup", prsMap); err != nil {
		return err
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, services.LogCleanerContainerName, host.Address); err != nil {
		return err
	}
	log.Debugf("[cleanup] Successfully cleaned up log links on host [%s]", host.Address)
	return nil
}
