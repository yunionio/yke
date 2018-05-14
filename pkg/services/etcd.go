package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	etcdclient "github.com/coreos/etcd/client"
	"github.com/pkg/errors"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	EtcdHealthCheckURL = "https://127.0.0.1:2379/health"
)

func RunEtcdPlane(ctx context.Context, etcdHosts []*hosts.Host, etcdProcessHostMap map[*hosts.Host]types.Process, localConnDialerFactory tunnel.DialerFactory, prsMap map[string]types.PrivateRegistry, updateWorkersOnly bool, alpineImage string) error {
	log.Infof("[%s] Building up etcd plane..", ETCDRole)
	for _, host := range etcdHosts {
		if updateWorkersOnly {
			continue
		}
		imageCfg, hostCfg, _ := GetProcessConfig(etcdProcessHostMap[host])
		if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, EtcdContainerName, host.Address, ETCDRole, prsMap); err != nil {
			return err
		}
		if err := createLogLink(ctx, host, EtcdContainerName, ETCDRole, alpineImage, prsMap); err != nil {
			return err
		}
	}
	log.Infof("[%s] Successfully started etcd plane..", ETCDRole)
	return nil
}

func RemoveEtcdPlane(ctx context.Context, etcdHosts []*hosts.Host, force bool) error {
	log.Infof("[%s] Tearing down etcd plane..", ETCDRole)
	for _, host := range etcdHosts {
		err := docker.DoRemoveContainer(ctx, host.DClient, EtcdContainerName, host.Address)
		if err != nil {
			return err
		}
		if !host.IsWorker || !host.IsControl || force {
			// remove unschedulable kubelet on etcd host
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
		}

	}
	log.Infof("[%s] Successfully tore down etcd plane..", ETCDRole)
	return nil
}

func AddEtcdMember(ctx context.Context, toAddEtcdHost *hosts.Host, etcdHosts []*hosts.Host, localConnDialerFactory tunnel.DialerFactory, cert, key []byte) error {
	log.Infof("[add/%s] Adding member [etcd-%s] to etcd cluster", ETCDRole, toAddEtcdHost.HostnameOverride)
	peerURL := fmt.Sprintf("https://%s:2380", toAddEtcdHost.InternalAddress)
	added := false
	for _, host := range etcdHosts {
		if host.Address == toAddEtcdHost.Address {
			continue
		}
		etcdClient, err := getEtcdClient(ctx, host, localConnDialerFactory, cert, key)
		if err != nil {
			log.Debugf("Failed to create etcd client for host [%s]: %v", host.Address, err)
			continue
		}
		memAPI := etcdclient.NewMembersAPI(etcdClient)
		if _, err := memAPI.Add(ctx, peerURL); err != nil {
			log.Debugf("Failed to Add etcd member [%s] from host: %v", host.Address, err)
			continue
		}
		added = true
		break
	}
	if !added {
		return fmt.Errorf("Failed to add etcd member [etcd-%s] to etcd cluster", toAddEtcdHost.HostnameOverride)
	}
	log.Infof("[add/%s] Successfully Added member [etcd-%s] to etcd cluster", ETCDRole, toAddEtcdHost.HostnameOverride)
	return nil
}

func RemoveEtcdMember(ctx context.Context, etcdHost *hosts.Host, etcdHosts []*hosts.Host, localConnDialerFactory tunnel.DialerFactory, cert, key []byte) error {
	log.Infof("[remove/%s] Removing member [etcd-%s] from etcd cluster", ETCDRole, etcdHost.HostnameOverride)
	var mID string
	removed := false
	for _, host := range etcdHosts {
		etcdClient, err := getEtcdClient(ctx, host, localConnDialerFactory, cert, key)
		if err != nil {
			log.Debugf("Failed to create etcd client for host [%s]: %v", host.Address, err)
			continue
		}
		memAPI := etcdclient.NewMembersAPI(etcdClient)
		members, err := memAPI.List(ctx)
		if err != nil {
			log.Debugf("Failed to list etcd members from host [%s]: %v", host.Address, err)
			continue
		}
		for _, member := range members {
			if member.Name == fmt.Sprintf("etcd-%s", etcdHost.HostnameOverride) {
				mID = member.ID
				break
			}
		}
		if err := memAPI.Remove(ctx, mID); err != nil {
			log.Debugf("Failed to list etcd members from host [%s]: %v", host.Address, err)
			continue
		}
		removed = true
		break
	}
	if !removed {
		return fmt.Errorf("Failed to delete etcd member [etcd-%s] from etcd cluster", etcdHost.HostnameOverride)
	}
	log.Infof("[remove/%s] Successfully removed member [etcd-%s] from etcd cluster", ETCDRole, etcdHost.HostnameOverride)
	return nil
}

func ReloadEtcdCluster(ctx context.Context, readyEtcdHosts []*hosts.Host, localConnDialerFactory tunnel.DialerFactory, cert, key []byte, prsMap map[string]types.PrivateRegistry, etcdProcessHostMap map[*hosts.Host]types.Process, alpineImage string) error {
	for host, process := range etcdProcessHostMap {
		imageCfg, hostCfg, _ := GetProcessConfig(process)
		if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, EtcdContainerName, host.Address, ETCDRole, prsMap); err != nil {
			return err
		}
		if err := createLogLink(ctx, host, EtcdContainerName, ETCDRole, alpineImage, prsMap); err != nil {
			return err
		}
	}
	time.Sleep(10 * time.Second)
	var healthy bool
	for _, host := range readyEtcdHosts {
		_, _, healthCheckURL := GetProcessConfig(etcdProcessHostMap[host])
		if healthy = isEtcdHealthy(ctx, localConnDialerFactory, host, cert, key, healthCheckURL); healthy {
			break
		}
	}
	if !healthy {
		return fmt.Errorf("[etcd] Etcd Cluster is not healthy")
	}
	return nil
}

func IsEtcdMember(ctx context.Context, etcdHost *hosts.Host, etcdHosts []*hosts.Host, localConnDialerFactory tunnel.DialerFactory, cert, key []byte) (bool, error) {
	var listErr error
	peerURL := fmt.Sprintf("https://%s:2380", etcdHost.InternalAddress)
	for _, host := range etcdHosts {
		if host.Address == etcdHost.Address {
			continue
		}
		etcdClient, err := getEtcdClient(ctx, host, localConnDialerFactory, cert, key)
		if err != nil {
			listErr = errors.Wrapf(err, "Failed to create etcd client for host [%s]", host.Address)
			log.Debugf("Failed to create etcd client for host [%s]: %v", host.Address, err)
			continue
		}
		memAPI := etcdclient.NewMembersAPI(etcdClient)
		members, err := memAPI.List(ctx)
		if err != nil {
			listErr = errors.Wrapf(err, "Failed to create etcd client for host [%s]", host.Address)
			log.Debugf("Failed to list etcd cluster members [%s]: %v", etcdHost.Address, err)
			continue
		}
		for _, member := range members {
			if strings.Contains(member.PeerURLs[0], peerURL) {
				log.Infof("[etcd] member [%s] is already part of the etcd cluster", etcdHost.Address)
				return true, nil
			}
		}
		// reset the list of errors to handle new hosts
		listErr = nil
		break
	}
	if listErr != nil {
		return false, listErr
	}
	return false, nil
}
