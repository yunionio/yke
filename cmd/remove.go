package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli"

	"yunion.io/x/log"

	"yunion.io/yke/pkg/cluster"
	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/types"
)

func RemoveCommand() cli.Command {
	removeFlags := []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Usage:  "Specify an alternate cluster YAML file",
			Value:  pki.ClusterConfig,
			EnvVar: "YKE_CONFIG",
		},
		cli.BoolFlag{
			Name:  "force",
			Usage: "Force removal of the cluster",
		},
		cli.BoolFlag{
			Name:  "local",
			Usage: "Deploy Kubernetes cluster locally",
		},
	}

	removeFlags = append(removeFlags, commonFlags...)

	return cli.Command{
		Name:   "remove",
		Usage:  "Teardown the cluster and clean cluster nodes",
		Action: clusterRemoveFromCli,
		Flags:  removeFlags,
	}
}

func ClusterRemove(
	ctx context.Context,
	ykeConfig *types.KubernetesEngineConfig,
	dialerFactory hosts.DialerFactory,
	k8sWrapTransport k8s.WrapTransport,
	local bool, configDir string) error {

	log.Infof("Tearing down Kubernetes cluster")
	kubeCluster, err := cluster.ParseCluster(ctx, ykeConfig, clusterFilePath, configDir, dialerFactory, nil, k8sWrapTransport)
	if err != nil {
		return err
	}

	err = kubeCluster.TunnelHosts(ctx, local)
	if err != nil {
		return err
	}

	log.Debugf("Starting Cluster removal")
	err = kubeCluster.ClusterRemove(ctx)
	if err != nil {
		return err
	}

	log.Infof("Cluster removed successfully")
	return nil
}

func clusterRemoveFromCli(ctx *cli.Context) error {
	force := ctx.Bool("force")
	if !force {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Are you sure you want to remove Kubernetes cluster [y/n]: ")
		input, err := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if err != nil {
			return err
		}
		if input != "y" && input != "Y" {
			return nil
		}
	}
	if ctx.Bool("local") {
		return clusterRemoveLocal(ctx)
	}
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

	return ClusterRemove(context.Background(), ykeConfig, nil, nil, false, "")
}

func clusterRemoveLocal(ctx *cli.Context) error {
	var ykeConfig *types.KubernetesEngineConfig
	clusterFile, filePath, err := resolveClusterFile(ctx)
	if err != nil {
		log.Infof("Failed to resolve cluster file, using default cluster instead")
		ykeConfig = cluster.GetLocalConfig()
	} else {
		clusterFilePath = filePath
		ykeConfig, err = cluster.ParseConfig(clusterFile)
		if err != nil {
			return fmt.Errorf("Failed to parse cluster file: %v", err)
		}
		ykeConfig.Nodes = []types.ConfigNode{*cluster.GetLocalNodeConfig()}
	}

	ykeConfig, err = setOptionsFromCLI(ctx, ykeConfig)
	if err != nil {
		return err
	}

	return ClusterRemove(context.Background(), ykeConfig, nil, nil, true, "")
}
