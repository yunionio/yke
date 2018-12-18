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

const (
	unschedulableEtcdTaint    = "node-role.kubernetes.io/etcd=true:NoExecute"
	unschedulableControlTaint = "node-role.kubernetes.io/controlplane=true:NoSchedule"
)

func RunWorkerPlane(
	ctx context.Context,
	allHosts []*hosts.Host,
	localConnDialerFactory hosts.DialerFactory,
	prsMap map[string]types.PrivateRegistry,
	workerNodePlanMap map[string]types.ConfigNodePlan,
	certMap map[string]pki.CertificatePKI,
	updateWorkersOnly bool,
	alpineImage string,
) error {
	log.Infof("[%s] Building up Worker Plane..", WorkerRole)
	var errgrp errgroup.Group

	hostsQueue := util.GetObjectQueue(allHosts)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				err := doDeployWorkerPlaneHost(ctx, runHost, localConnDialerFactory, prsMap, workerNodePlanMap[runHost.Address].Processes, certMap, updateWorkersOnly, alpineImage)
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
	log.Infof("[%s] Successfully started Worker Plane...", WorkerRole)
	return nil
}

func doDeployWorkerPlaneHost(ctx context.Context, host *hosts.Host, localConnDialerFactory hosts.DialerFactory, prsMap map[string]types.PrivateRegistry, processMap map[string]types.Process, certMap map[string]pki.CertificatePKI, updateWorkersOnly bool, alpineImage string) error {
	if updateWorkersOnly {
		if !host.UpdateWorker {
			return nil
		}
	}
	if !host.IsWorker {
		if host.IsEtcd {
			// Add unschedulable taint
			host.ToAddTaints = append(host.ToAddTaints, unschedulableEtcdTaint)
		}
		if host.IsControl {
			// Add unschedulable taint
			host.ToAddTaints = append(host.ToAddTaints, unschedulableControlTaint)
		}
	}
	return doDeployWorkerPlane(ctx, host, localConnDialerFactory, prsMap, processMap, certMap, alpineImage)
}

func RemoveWorkerPlane(ctx context.Context, workerHosts []*hosts.Host, force bool) error {
	log.Infof("[%s] Tearing down Worker Plane..", WorkerRole)
	var errgrp errgroup.Group
	hostsQueue := util.GetObjectQueue(workerHosts)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				if runHost.IsControl && !force {
					log.Infof("[%s] Host [%s] is already a controlplane host, nothing to do.", WorkerRole, runHost.Address)
					return nil
				}

				if err := removeKubelet(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := removeKubeproxy(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := removeNginxProxy(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := removeSidekick(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := removeK8sContainer(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
		})
	}

	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("[%s] Successfully tore down Worker Plane..", WorkerRole)
	return nil
}

func doDeployWorkerPlane(ctx context.Context, host *hosts.Host,
	localConnDialerFactory hosts.DialerFactory,
	prsMap map[string]types.PrivateRegistry, processMap map[string]types.Process, certMap map[string]pki.CertificatePKI, alpineImage string) error {
	// run nginx proxy
	if !host.IsControl {
		if err := runNginxProxy(ctx, host, prsMap, processMap[NginxProxyContainerName], alpineImage); err != nil {
			return err
		}
	}
	// run sidekick
	if err := runSidekick(ctx, host, prsMap, processMap[SidekickContainerName]); err != nil {
		return err
	}
	// run kubelet
	if err := runKubelet(ctx, host, localConnDialerFactory, prsMap, processMap[KubeletContainerName], certMap, alpineImage); err != nil {
		return err
	}
	return runKubeproxy(ctx, host, localConnDialerFactory, prsMap, processMap[KubeproxyContainerName], alpineImage)
}

func copyProcessMap(m map[string]types.Process) map[string]types.Process {
	c := make(map[string]types.Process)
	for k, v := range m {
		c[k] = v
	}
	return c
}

func RestartWorkerPlane(ctx context.Context, workerHosts []*hosts.Host) error {
	log.Infof("[%s] Restarting Worker Plane..", WorkerRole)
	var errgrp errgroup.Group

	hostsQueue := util.GetObjectQueue(workerHosts)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				runHost := host.(*hosts.Host)
				if err := restartKubelet(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := restartKubeproxy(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
				if err := restartNginxProxy(ctx, runHost); err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("[%s] Successfully restarted Worker Plane..", WorkerRole)

	return nil
}
