package services

import (
	"context"

	"golang.org/x/sync/errgroup"

	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

func RunControlPlane(ctx context.Context, controlHosts []*hosts.Host, localConnDialerFactory tunnel.DialerFactory, prsMap map[string]types.PrivateRegistry, processMap map[string]types.Process, updateWorkersOnly bool, alpineImage string) error {
	log.Infof("[%s] Building up Controller Plane..", ControlRole)
	var errgrp errgroup.Group
	for _, host := range controlHosts {
		runHost := host
		if updateWorkersOnly {
			continue
		}
		errgrp.Go(func() error {
			return doDeployControlHost(ctx, runHost, localConnDialerFactory, prsMap, processMap, alpineImage)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("[%s] Successfully started Controller Plane..", ControlRole)
	return nil
}

func RemoveControlPlane(ctx context.Context, controlHosts []*hosts.Host, force bool) error {
	log.Infof("[%s] Tearing down the Controller Plane..", ControlRole)
	for _, host := range controlHosts {
		// remove KubeAPI
		if err := removeKubeAPI(ctx, host); err != nil {
			return err
		}

		// remove KubeController
		if err := removeKubeController(ctx, host); err != nil {
			return nil
		}

		// remove scheduler
		err := removeScheduler(ctx, host)
		if err != nil {
			return err
		}

		// check if the host already is a worker
		if host.IsWorker {
			log.Infof("[%s] Host [%s] is already a worker host, skipping delete kubelet and kubeproxy.", ControlRole, host.Address)
		} else {
			// remove KubeAPI
			if err := removeKubelet(ctx, host); err != nil {
				return err
			}
			// remove KubeController
			if err := removeKubeproxy(ctx, host); err != nil {
				return nil
			}
			// remove Sidekick
			if err := removeSidekick(ctx, host); err != nil {
				return err
			}
		}
	}
	log.Infof("[%s] Successfully tore down Controller Plane..", ControlRole)
	return nil
}

func doDeployControlHost(ctx context.Context, host *hosts.Host, localConnDialerFactory tunnel.DialerFactory, prsMap map[string]types.PrivateRegistry, processMap map[string]types.Process, alpineImage string) error {
	if host.IsWorker {
		if err := removeNginxProxy(ctx, host); err != nil {
			return err
		}
	}
	// run sidekick
	if err := runSidekick(ctx, host, prsMap, processMap[SidekickContainerName]); err != nil {
		return err
	}
	// run kubeapi
	if err := runKubeAPI(ctx, host, localConnDialerFactory, prsMap, processMap[KubeAPIContainerName], alpineImage); err != nil {
		return err
	}
	// run kubecontroller
	if err := runKubeController(ctx, host, localConnDialerFactory, prsMap, processMap[KubeControllerContainerName], alpineImage); err != nil {
		return err
	}
	// run scheduler
	return runScheduler(ctx, host, localConnDialerFactory, prsMap, processMap[SchedulerContainerName], alpineImage)
}
