package services

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	etcdclient "github.com/coreos/etcd/client"
	"github.com/docker/docker/api/types/container"
	"github.com/pkg/errors"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/types"
)

const (
	EtcdSnapshotPath = "/opt/yke/etcd-snapshots/"
	EtcdRestorePath  = "/opt/yke/etcd-snapshots-restore/"
	EtcdDataDir      = "/var/lib/yunion/etcd/"
)

type EtcdSnapshot struct {
	// Enable or disable snapshot creation
	Snapshot bool
	// Creation period of the etcd snapshots
	Creation string
	// Retention period of the etcd snapshots
	Retention string
}

func RunEtcdPlane(
	ctx context.Context,
	etcdHosts []*hosts.Host,
	etcdNodePlanMap map[string]types.ConfigNodePlan,
	localConnDialerFactory hosts.DialerFactory,
	prsMap map[string]types.PrivateRegistry,
	updateWorkersOnly bool,
	alpineImage string,
	etcdSnapshot EtcdSnapshot,
) error {
	log.Infof("[%s] Building up etcd plane..", ETCDRole)
	for _, host := range etcdHosts {
		if updateWorkersOnly {
			continue
		}
		etcdProcess := etcdNodePlanMap[host.Address].Processes[EtcdContainerName]
		imageCfg, hostCfg, _ := GetProcessConfig(etcdProcess)
		if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, EtcdContainerName, host.Address, ETCDRole, prsMap); err != nil {
			return err
		}
		if etcdSnapshot.Snapshot {
			if err := RunEtcdSnapshotSave(ctx, host, prsMap, alpineImage, etcdSnapshot.Creation, etcdSnapshot.Retention, EtcdSnapshotContainerName, false); err != nil {
				return err
			}
			if err := pki.SaveBackupBundleOnHost(ctx, host, alpineImage, EtcdSnapshotPath, prsMap); err != nil {
				return err
			}
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

func AddEtcdMember(ctx context.Context, toAddEtcdHost *hosts.Host, etcdHosts []*hosts.Host, localConnDialerFactory hosts.DialerFactory, cert, key []byte) error {
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

func RemoveEtcdMember(ctx context.Context, etcdHost *hosts.Host, etcdHosts []*hosts.Host, localConnDialerFactory hosts.DialerFactory, cert, key []byte) error {
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

func ReloadEtcdCluster(ctx context.Context, readyEtcdHosts []*hosts.Host, localConnDialerFactory hosts.DialerFactory, cert, key []byte, prsMap map[string]types.PrivateRegistry, etcdNodePlanMap map[string]types.ConfigNodePlan, alpineImage string) error {
	for _, etcdHost := range readyEtcdHosts {
		imageCfg, hostCfg, _ := GetProcessConfig(etcdNodePlanMap[etcdHost.Address].Processes[EtcdContainerName])
		if err := docker.DoRunContainer(ctx, etcdHost.DClient, imageCfg, hostCfg, EtcdContainerName, etcdHost.Address, ETCDRole, prsMap); err != nil {
			return err
		}
		if err := createLogLink(ctx, etcdHost, EtcdContainerName, ETCDRole, alpineImage, prsMap); err != nil {
			return err
		}
	}
	time.Sleep(10 * time.Second)
	var healthy bool
	for _, host := range readyEtcdHosts {
		_, _, healthCheckURL := GetProcessConfig(etcdNodePlanMap[host.Address].Processes[EtcdContainerName])
		if healthy = isEtcdHealthy(ctx, localConnDialerFactory, host, cert, key, healthCheckURL); healthy {
			break
		}
	}
	if !healthy {
		return fmt.Errorf("[etcd] Etcd Cluster is not healthy")
	}
	return nil
}

func IsEtcdMember(ctx context.Context, etcdHost *hosts.Host, etcdHosts []*hosts.Host, localConnDialerFactory hosts.DialerFactory, cert, key []byte) (bool, error) {
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

func RunEtcdSnapshotSave(ctx context.Context, etcdHost *hosts.Host, prsMap map[string]types.PrivateRegistry, etcdSnapshotImage string, creation, retention, name string, once bool) error {
	log.Infof("[etcd] Saving snapshot [%s] on host [%s]", name, etcdHost.Address)
	imageCfg := &container.Config{
		Cmd: []string{
			"/opt/yke-tools/yke-etcd-backup",
			"rolling-backup",
			"--cacert", pki.GetCertPath(pki.CACertName),
			"--cert", pki.GetCertPath(pki.KubeNodeCertName),
			"--key", pki.GetKeyPath(pki.KubeNodeCertName),
			"--name", name,
			"--endpoints=" + etcdHost.InternalAddress + ":2379",
		},
		Image: etcdSnapshotImage,
	}
	if once {
		imageCfg.Cmd = append(imageCfg.Cmd, "--once")
	}
	if !once {
		imageCfg.Cmd = append(imageCfg.Cmd, "--retention="+retention)
		imageCfg.Cmd = append(imageCfg.Cmd, "--creation="+creation)
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/backup", EtcdSnapshotPath),
			fmt.Sprintf("%s:/etc/kubernetes:z", path.Join(etcdHost.PrefixPath, "/etc/kubernetes"))},
		NetworkMode: container.NetworkMode("host"),
	}

	if once {
		if err := docker.DoRunContainer(ctx, etcdHost.DClient, imageCfg, hostCfg, EtcdSnapshotOnceContainerName, etcdHost.Address, ETCDRole, prsMap); err != nil {
			return err
		}
		status, err := docker.WaitForContainer(ctx, etcdHost.DClient, etcdHost.Address, EtcdSnapshotOnceContainerName)
		if status != 0 || err != nil {
			return fmt.Errorf("Failed to take etcd snapshot exit code [%d]: %v", status, err)
		}
		return docker.RemoveContainer(ctx, etcdHost.DClient, etcdHost.Address, EtcdSnapshotOnceContainerName)
	}
	return docker.DoRunContainer(ctx, etcdHost.DClient, imageCfg, hostCfg, EtcdSnapshotContainerName, etcdHost.Address, ETCDRole, prsMap)
}

func RestoreEtcdSnapshot(ctx context.Context, etcdHost *hosts.Host, prsMap map[string]types.PrivateRegistry, etcdRestoreImage, snapshotName, initCluster string) error {
	log.Infof("[etcd] Restoring [%s] snapshot on etcd host [%s]", snapshotName, etcdHost.Address)
	nodeName := pki.GetEtcdCrtName(etcdHost.InternalAddress)
	snapshotPath := fmt.Sprintf("%s%s", EtcdSnapshotPath, snapshotName)

	// make sure that retore path is empty otherwirse etcd restore will fail
	imageCfg := &container.Config{
		Cmd: []string{
			"sh", "-c", strings.Join([]string{
				"rm -rf", EtcdRestorePath,
				"&& /usr/local/bin/etcdctl",
				fmt.Sprintf("--endpoints=[%s:2379]", etcdHost.InternalAddress),
				"--cacert", pki.GetCertPath(pki.CACertName),
				"--cert", pki.GetCertPath(nodeName),
				"--key", pki.GetKeyPath(nodeName),
				"snapshot", "restore", snapshotPath,
				"--data-dir=" + EtcdRestorePath,
				"--name=etcd-" + etcdHost.HostnameOverride,
				"--initial-cluster=" + initCluster,
				"--initial-cluster-token=etcd-cluster-1",
				"--initial-advertise-peer-urls=https://" + etcdHost.InternalAddress + ":2380",
				"&& mv", EtcdRestorePath + "*", EtcdDataDir,
				"&& rm -rf", EtcdRestorePath,
			}, " "),
		},
		Env:   []string{"ETCDCTL_API=3"},
		Image: etcdRestoreImage,
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			"/opt/yke:/opt/yke/:z",
			fmt.Sprintf("%s:/var/lib/yunion/etcd:z", path.Join(etcdHost.PrefixPath, "/var/lib/etcd")),
			fmt.Sprintf("%s:/etc/kubernetes:z", path.Join(etcdHost.PrefixPath, "/etc/kubernetes"))},
		NetworkMode: container.NetworkMode("host"),
	}
	if err := docker.DoRunContainer(ctx, etcdHost.DClient, imageCfg, hostCfg, EtcdRestoreContainerName, etcdHost.Address, ETCDRole, prsMap); err != nil {
		return err
	}
	status, err := docker.WaitForContainer(ctx, etcdHost.DClient, etcdHost.Address, EtcdRestoreContainerName)
	if err != nil {
		return err
	}
	if status != 0 {
		containerLog, err := docker.GetContainerLogsStdoutStderr(ctx, etcdHost.DClient, EtcdRestoreContainerName, "5", false)
		if err != nil {
			return err
		}
		if err := docker.RemoveContainer(ctx, etcdHost.DClient, etcdHost.Address, EtcdRestoreContainerName); err != nil {
			return err
		}
		// printing the restore container's logs
		return fmt.Errorf("Failed to run etcd restore contaienr, exist status is: %d, container logs: %s", status, containerLog)
	}
	return docker.RemoveContainer(ctx, etcdHost.DClient, etcdHost.Address, EtcdRestoreContainerName)
}
