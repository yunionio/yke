package services

import (
	"context"

	"golang.org/x/sync/errgroup"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/types"
	"yunion.io/x/yke/pkg/util"
)

func RunControlPlane(
	ctx context.Context,
	controlHosts []*hosts.Host,
	localConnDialerFactory hosts.DialerFactory,
	prsMap map[string]types.PrivateRegistry,
	cpNodePlanMap map[string]types.ConfigNodePlan,
	updateWorkersOnly bool,
	alpineImage string,
	certMap map[string]pki.CertificatePKI) error {
	if updateWorkersOnly {
		return nil
	}
	log.Infof("[%s] Building up Controller Plane..", ControlRole)
	var errgrp errgroup.Group
	hostsQueue := util.GetObjectQueue(controlHosts)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				err := doDeployControlHost(ctx, runHost, localConnDialerFactory, prsMap, cpNodePlanMap[runHost.Address].Processes, alpineImage, certMap)
				if err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
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
	var errgrp errgroup.Group
	hostsQueue := util.GetObjectQueue(controlHosts)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				if err := removeKubeAPI(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := removeKubeController(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := removeScheduler(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				// force is true in remove, false in reconcile
				if force {
					if err := removeKubelet(ctx, runHost); err != nil {
						errList = append(errList, err)
					}
					if err := removeKubeproxy(ctx, runHost); err != nil {
						errList = append(errList, err)
					}
					if err := removeSidekick(ctx, runHost); err != nil {
						errList = append(errList, err)
					}
				}
			}
			return util.ErrList(errList)
		})
	}

	if err := errgrp.Wait(); err != nil {
		return err
	}

	log.Infof("[%s] Successfully tore down Controller Plane..", ControlRole)
	return nil
}

func RestartControlPlane(ctx context.Context, controlHosts []*hosts.Host) error {
	log.Infof("[%s] Restarting the Controller Plane..", ControlRole)
	var errgrp errgroup.Group

	hostsQueue := util.GetObjectQueue(controlHosts)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				// restart KubeAPI
				if err := restartKubeAPI(ctx, runHost); err != nil {
					errList = append(errList, err)
				}

				// restart KubeController
				if err := restartKubeController(ctx, runHost); err != nil {
					errList = append(errList, err)
				}

				// restart scheduler
				err := restartScheduler(ctx, runHost)
				if err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("[%s] Successfully restarted Controller Plane..", ControlRole)
	return nil
}

func doDeployControlHost(
	ctx context.Context,
	host *hosts.Host,
	localConnDialerFactory hosts.DialerFactory,
	prsMap map[string]types.PrivateRegistry,
	processMap map[string]types.Process,
	alpineImage string,
	certMap map[string]pki.CertificatePKI,
) error {
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
	if err := runKubeAPI(ctx, host, localConnDialerFactory, prsMap, processMap[KubeAPIContainerName], alpineImage, certMap); err != nil {
		return err
	}
	// run kubecontroller
	if err := runKubeController(ctx, host, localConnDialerFactory, prsMap, processMap[KubeControllerContainerName], alpineImage); err != nil {
		return err
	}
	// run scheduler
	if err := runScheduler(ctx, host, localConnDialerFactory, prsMap, processMap[SchedulerContainerName], alpineImage); err != nil {
		return err
	}
	return nil
}
