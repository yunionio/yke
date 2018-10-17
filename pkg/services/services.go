package services

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/types"
)

const (
	ETCDRole    = "etcd"
	ControlRole = "controlplane"
	WorkerRole  = "worker"

	SidekickServiceName   = "sidekick"
	RBACAuthorizationMode = "rbac"

	KubeAPIContainerName          = "kube-apiserver"
	KubeletContainerName          = "kubelet"
	KubeproxyContainerName        = "kube-proxy"
	KubeControllerContainerName   = "kube-controller-manager"
	SchedulerContainerName        = "kube-scheduler"
	EtcdContainerName             = "etcd"
	EtcdSnapshotContainerName     = "etcd-rolling-snapshots"
	EtcdSnapshotOnceContainerName = "etcd-snapshot-once"
	EtcdRestoreContainerName      = "etcd-restore"
	NginxProxyContainerName       = "nginx-proxy"
	SidekickContainerName         = "service-sidekick"
	LXCFSContainerName            = "lxcfs"
	LogLinkContainerName          = "log-linker"
	LogCleanerContainerName       = "log-cleaner"

	KubeAPIPort        = 6443
	SchedulerPort      = 10251
	KubeControllerPort = 10252
	KubeletPort        = 10250
	KubeproxyPort      = 10256

	LogsPath = "/var/lib/yunion/yke/log"
)

func runSidekick(ctx context.Context, host *hosts.Host, prsMap map[string]types.PrivateRegistry, sidecarProcess types.Process) error {
	isRunning, err := docker.IsContainerRunning(ctx, host.DClient, host.Address, SidekickContainerName, true)
	if err != nil {
		return err
	}
	imageCfg, hostCfg, _ := GetProcessConfig(sidecarProcess)
	isUpgradable := false
	if isRunning {
		isUpgradable, err = docker.IsContainerUpgradable(ctx, host.DClient, imageCfg, hostCfg, SidekickContainerName, host.Address, SidekickServiceName)
		if err != nil {
			return err
		}
		if !isUpgradable {
			log.Infof("[%s] Sidekick container already created on host [%s]", SidekickServiceName, host.Address)
			return nil
		}
	}

	if err := docker.UseLocalOrPull(ctx, host.DClient, host.Address, sidecarProcess.Image, SidekickServiceName, prsMap); err != nil {
		return err
	}
	if isUpgradable {
		if err := docker.DoRemoveContainer(ctx, host.DClient, SidekickContainerName, host.Address); err != nil {
			return err
		}
	}
	if _, err := docker.CreateContainer(ctx, host.DClient, host.Address, SidekickContainerName, imageCfg, hostCfg); err != nil {
		return err
	}
	return nil
}

func removeSidekick(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, SidekickContainerName, host.Address)
}

func runLXCFS(ctx context.Context, host *hosts.Host, prsMap map[string]types.PrivateRegistry, lxcfsProcess types.Process) error {
	imageCfg, hostCfg, _ := GetProcessConfig(lxcfsProcess)
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, LXCFSContainerName, host.Address, WorkerRole, prsMap); err != nil {
		return err
	}
	return nil
}

func removeLXCFS(ctx context.Context, host *hosts.Host) error {
	return docker.DoRemoveContainer(ctx, host.DClient, LXCFSContainerName, host.Address)
}

func removeK8sContainer(ctx context.Context, host *hosts.Host) error {
	containers, err := docker.GetK8sContainer(ctx, host.DClient)
	if err != nil {
		return nil
	}
	for _, container := range containers {
		err = docker.DoRemoveContainer(ctx, host.DClient, container.Names[0], host.Address)
		if err != nil {
			log.Errorf("Remove k8s container %#v error: %v", container, err)
			return err
		}
	}
	return nil
}

func GetProcessConfig(process types.Process) (*container.Config, *container.HostConfig, string) {
	imageCfg := &container.Config{
		Entrypoint: process.Command,
		Cmd:        process.Args,
		Env:        process.Env,
		Image:      process.Image,
		Labels:     process.Labels,
	}
	// var pidMode container.PidMode
	// pidMode = process.PidMode
	_, portBindings, _ := nat.ParsePortSpecs(process.Publish)
	hostCfg := &container.HostConfig{
		VolumesFrom:  process.VolumesFrom,
		Binds:        process.Binds,
		NetworkMode:  container.NetworkMode(process.NetworkMode),
		PidMode:      container.PidMode(process.PidMode),
		Privileged:   process.Privileged,
		PortBindings: portBindings,
	}
	if len(process.RestartPolicy) > 0 {
		hostCfg.RestartPolicy = container.RestartPolicy{Name: process.RestartPolicy}
	}
	return imageCfg, hostCfg, process.HealthCheck.URL
}

func GetHealthCheckURL(useTLS bool, port int) string {
	if useTLS {
		return fmt.Sprintf("%s%s:%d%s", HTTPSProtoPrefix, HealthzAddress, port, HealthzEndpoint)
	}
	return fmt.Sprintf("%s%s:%d%s", HTTPProtoPrefix, HealthzAddress, port, HealthzEndpoint)
}

func createLogLink(ctx context.Context, host *hosts.Host, containerName, plane, image string, prsMap map[string]types.PrivateRegistry) error {
	log.Debugf("[%s] Creating log link for Container [%s] on host [%s]", plane, containerName, host.Address)
	containerInspect, err := docker.InspectContainer(ctx, host.DClient, host.Address, containerName)
	if err != nil {
		return err
	}
	containerID := containerInspect.ID
	containerLogPath := containerInspect.LogPath
	containerLogLink := fmt.Sprintf("%s/%s_%s.log", hosts.YKELogsPath, containerName, containerID)
	imageCfg := &container.Config{
		Image: image,
		Tty:   true,
		Cmd: []string{
			"sh",
			"-c",
			fmt.Sprintf("mkdir -p %s ; ln -s %s %s", hosts.YKELogsPath, containerLogPath, containerLogLink),
		},
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			"/var/lib:/var/lib",
		},
		Privileged: true,
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, LogLinkContainerName, host.Address); err != nil {
		return err
	}
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, LogLinkContainerName, host.Address, plane, prsMap); err != nil {
		return err
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, LogLinkContainerName, host.Address); err != nil {
		return err
	}
	log.Debugf("[%s] Successfully created log link for Container [%s] on host [%s]", plane, containerName, host.Address)
	return nil
}
