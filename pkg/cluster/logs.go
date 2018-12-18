package cluster

import (
	"context"

	"golang.org/x/sync/errgroup"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/util"
)

func (c *Cluster) CleanDeadLogs(ctx context.Context) error {
	hostList := hosts.GetUniqueHostList(c.EtcdHosts, c.ControlPlaneHosts, c.WorkerHosts)

	var errgrp errgroup.Group
	hostsQueue := util.GetObjectQueue(hostList)
	for w := 0; w < WorkerThreads; w++ {
		errgrp.Go(func() error {
			var errList []error
			for host := range hostsQueue {
				err := hosts.DoRunLogCleaner(ctx, host.(*hosts.Host), c.SystemImages.Alpine, c.PrivateRegistriesMap)
				if err != nil {
					errList = append(errList, err)
				}
			}
			return util.ErrList(errList)
		})
	}

	return errgrp.Wait()
}
