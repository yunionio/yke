package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/cluster"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/k8s"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/services"
	"yunion.io/x/yke/pkg/types"
)

func CertificateCommand() cli.Command {
	return cli.Command{
		Name:  "cert",
		Usage: "Certificates management for YKE cluster",
		Subcommands: cli.Commands{
			cli.Command{
				Name:   "rotate",
				Usage:  "Rotate YKE cluster certificates",
				Action: rotateKECertificatesFromCli,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:   "config",
						Usage:  "Specify an alternate cluster YAML file",
						Value:  pki.ClusterConfig,
						EnvVar: "YKE_CONFIG",
					},
					cli.StringSliceFlag{
						Name: "service",
						Usage: fmt.Sprintf("Specify a k8s service to rotate certs, (allowed values: %s, %s, %s, %s, %s, %s)",
							services.KubeAPIContainerName,
							services.KubeControllerContainerName,
							services.SchedulerContainerName,
							services.KubeletContainerName,
							services.KubeproxyContainerName,
							services.EtcdContainerName,
						),
					},
					cli.BoolFlag{
						Name:  "rotate-ca",
						Usage: "Rotate all certificates including CA certs",
					},
				},
			},
		},
	}
}

func rotateKECertificatesFromCli(ctx *cli.Context) error {
	k8sComponent := ctx.StringSlice("service")
	rotateCACert := ctx.Bool("rotate-ca")
	clusterFile, filePath, err := resolveClusterFile(ctx)
	if err != nil {
		return fmt.Errorf("Failed to resolve cluster file: %v", err)
	}
	clusterFilePath = filePath

	keConfig, err := cluster.ParseConfig(clusterFile)
	if err != nil {
		return fmt.Errorf("Failed to parse cluster file: %v", err)
	}
	keConfig, err = setOptionsFromCLI(ctx, keConfig)
	if err != nil {
		return err
	}

	return RotateKECertificates(context.Background(), keConfig, nil, nil, nil, false, "", k8sComponent, rotateCACert)
}

func showRKECertificatesFromCli(ctx *cli.Context) error {
	return nil
}

func RotateKECertificates(
	ctx context.Context,
	keConfig *types.KubernetesEngineConfig,
	dockerDialerFactory, localConnDialerFactory hosts.DialerFactory,
	k8sWrapTransport k8s.WrapTransport,
	local bool, configDir string, components []string, rotateCACerts bool) error {

	log.Infof("Rotating Kubernetes cluster certificates")
	kubeCluster, err := cluster.ParseCluster(ctx, keConfig, clusterFilePath, configDir, dockerDialerFactory, localConnDialerFactory, k8sWrapTransport)
	if err != nil {
		return err
	}

	if err := kubeCluster.TunnelHosts(ctx, local); err != nil {
		return err
	}

	currentCluster, err := kubeCluster.GetClusterState(ctx)
	if err != nil {
		return err
	}

	if err := cluster.SetUpAuthentication(ctx, kubeCluster, currentCluster); err != nil {
		return err
	}

	if err := cluster.RotateKECertificates(ctx, kubeCluster, clusterFilePath, configDir, components, rotateCACerts); err != nil {
		return err
	}

	if err := kubeCluster.SetUpHosts(ctx, true); err != nil {
		return err
	}
	// Restarting Kubernetes components
	servicesMap := make(map[string]bool)
	for _, component := range components {
		servicesMap[component] = true
	}

	if len(components) == 0 || rotateCACerts || servicesMap[services.EtcdContainerName] {
		if err := services.RestartEtcdPlane(ctx, kubeCluster.EtcdHosts); err != nil {
			return err
		}
	}

	if err := services.RestartControlPlane(ctx, kubeCluster.ControlPlaneHosts); err != nil {
		return err
	}

	allHosts := hosts.GetUniqueHostList(kubeCluster.EtcdHosts, kubeCluster.ControlPlaneHosts, kubeCluster.WorkerHosts)
	if err := services.RestartWorkerPlane(ctx, allHosts); err != nil {
		return err
	}

	if err := kubeCluster.SaveClusterState(ctx, &kubeCluster.KubernetesEngineConfig); err != nil {
		return err
	}

	if rotateCACerts {
		return cluster.RestartClusterPods(ctx, kubeCluster)
	}
	return nil
}
