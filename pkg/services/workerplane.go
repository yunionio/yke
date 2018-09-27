package services

import (
	"context"

	"golang.org/x/sync/errgroup"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/types"
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
	for _, host := range allHosts {
		if updateWorkersOnly {
			if !host.UpdateWorker {
				continue
			}
		}
		if !host.IsWorker {
			if host.IsEtcd {
				// Add unschedulable taint
				host.ToAddTaints = append(host.ToAddTaints, unschedulableEtcdTaint)
			}
			if host.IsControl {
				// Add unscheduable taint
				host.ToAddTaints = append(host.ToAddTaints, unschedulableControlTaint)
			}
		}
		runHost := host
		// maps are not thread safe
		hostProcessMap := copyProcessMap(workerNodePlanMap[runHost.Address].Processes)
		errgrp.Go(func() error {
			return doDeployWorkerPlane(ctx, runHost, localConnDialerFactory, prsMap, hostProcessMap, certMap, alpineImage)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err
	}
	log.Infof("[%s] Successfully started Worker Plane...", WorkerRole)
	return nil
}

func RemoveWorkerPlane(ctx context.Context, workerHosts []*hosts.Host, force bool) error {
	log.Infof("[%s] Tearing down Worker Plane..", WorkerRole)
	for _, host := range workerHosts {
		// check if the host already is a controlplane
		if host.IsControl && !force {
			log.Infof("[%s] Host [%s] is already a controlplane host, nothing to do.", WorkerRole, host.Address)
			return nil
		}

		if err := removeKubelet(ctx, host); err != nil {
			return err
		}
		if err := removeKubeproxy(ctx, host); err != nil {
			return err
		}
		if err := removeNginxProxy(ctx, host); err != nil {
			return err
		}
		if err := removeSidekick(ctx, host); err != nil {
			return err
		}
		log.Infof("[%s] Successfully tore down Worker Plane..", WorkerRole)
	}

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
