package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/urfave/cli"

	"yunion.io/x/log"

	"yunion.io/yke/pkg/cluster"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/types"
)

func EtcdCommand() cli.Command {
	snapshotFlags := []cli.Flag{
		cli.StringFlag{
			Name:  "name",
			Usage: "Specify Snapshot name",
		},
		cli.StringFlag{
			Name:   "config",
			Usage:  "Specify an alternate cluster YAML file",
			Value:  pki.ClusterConfig,
			EnvVar: "YKE_CONFIG",
		},
	}

	snapshotFlags = append(snapshotFlags, commonFlags...)

	return cli.Command{
		Name:  "etcd",
		Usage: "etcd snapshot save/restore operations in k8s cluster",
		Subcommands: []cli.Command{
			{
				Name:   "snapshot-save",
				Usage:  "Take snapshot on all etcd hosts",
				Flags:  snapshotFlags,
				Action: SnapshotSaveEtcdHostsFromCli,
			},
			{
				Name:   "snapshot-restore",
				Usage:  "Restore existing snapshot",
				Flags:  snapshotFlags,
				Action: RestoreEtcdSnapshotFromCli,
			},
		},
	}
}

func SnapshotSaveEtcdHosts(
	ctx context.Context,
	ykeConfig *types.KubernetesEngineConfig,
	dockerDialerFactory hosts.DialerFactory,
	configDir, snapshotName string) error {

	log.Infof("Starting saving snapshot on etcd hosts")
	kubeCluster, err := cluster.ParseCluster(ctx, ykeConfig, clusterFilePath, configDir, dockerDialerFactory, nil, nil)
	if err != nil {
		return err
	}

	if err := kubeCluster.TunnelHosts(ctx, false); err != nil {
		return err
	}
	if err := kubeCluster.SnapshotEtcd(ctx, snapshotName); err != nil {
		return err
	}

	if err := kubeCluster.SaveBackupCertificateBundle(ctx); err != nil {
		return err
	}

	log.Infof("Finished saving snapshot [%s] on all etcd hosts", snapshotName)
	return nil
}

func RestoreEtcdSnapshot(
	ctx context.Context,
	ykeConfig *types.KubernetesEngineConfig,
	dockerDialerFactory hosts.DialerFactory,
	configDir, snapshotName string) error {

	log.Infof("Starting restoring snapshot on etcd hosts")
	kubeCluster, err := cluster.ParseCluster(ctx, ykeConfig, clusterFilePath, configDir, dockerDialerFactory, nil, nil)
	if err != nil {
		return err
	}

	if err := kubeCluster.TunnelHosts(ctx, false); err != nil {
		return err
	}
	if err := kubeCluster.RestoreEtcdSnapshot(ctx, snapshotName); err != nil {
		return err
	}
	if err := kubeCluster.ExtractBackupCertificateBundle(ctx); err != nil {
		return err
	}
	log.Infof("Finished restoring snapshot [%s] on all etcd hosts", snapshotName)
	return nil
}

func SnapshotSaveEtcdHostsFromCli(ctx *cli.Context) error {
	clusterFile, filePath, err := resolveClusterFile(ctx)
	if err != nil {
		return fmt.Errorf("Failed to resolve cluster file: %v", err)
	}
	clusterFilePath = filePath

	ykeConfig, err := cluster.ParseConfig(clusterFile)
	if err != nil {
		return fmt.Errorf("Failed to parse cluster file: %v", err)
	}

	ykeConfig, err = setOptionsFromCLI(ctx, ykeConfig)
	if err != nil {
		return err
	}
	// Check snapshot name
	etcdSnapshotName := ctx.String("name")
	if etcdSnapshotName == "" {
		etcdSnapshotName = fmt.Sprintf("yke_etcd_snapshot_%s", time.Now().Format(time.RFC3339))
		log.Warningf("Name of the snapshot is not specified using [%s]", etcdSnapshotName)
	}
	return SnapshotSaveEtcdHosts(context.Background(), ykeConfig, nil, "", etcdSnapshotName)
}

func RestoreEtcdSnapshotFromCli(ctx *cli.Context) error {
	clusterFile, filePath, err := resolveClusterFile(ctx)
	if err != nil {
		return fmt.Errorf("Failed to resolve cluster file: %v", err)
	}
	clusterFilePath = filePath

	ykeConfig, err := cluster.ParseConfig(clusterFile)
	if err != nil {
		return fmt.Errorf("Failed to parse cluster file: %v", err)
	}

	ykeConfig, err = setOptionsFromCLI(ctx, ykeConfig)
	if err != nil {
		return err
	}
	etcdSnapshotName := ctx.String("name")
	if etcdSnapshotName == "" {
		return fmt.Errorf("You must specify the snapshot name to restore")
	}
	return RestoreEtcdSnapshot(context.Background(), ykeConfig, nil, "", etcdSnapshotName)
}
