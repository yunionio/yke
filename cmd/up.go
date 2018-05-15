package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli"
	"k8s.io/client-go/util/cert"

	"yunion.io/yke/pkg/cluster"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

var clusterFilePath string

func UpCommand() cli.Command {
	upFlags := []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Usage:  "Specify an alternate cluster YAML file",
			Value:  pki.ClusterConfig,
			EnvVar: "YKE_CONFIG",
		},
		cli.BoolFlag{
			Name:  "local",
			Usage: "Deploy Kubernetes cluster locally",
		},
		cli.BoolFlag{
			Name:  "update-only",
			Usage: "Skip idempotent deployment of control and etcd plane",
		},
		cli.BoolFlag{
			Name:  "disable-port-check",
			Usage: "Disable port check validation between nodes",
		},
	}

	upFlags = append(upFlags, sshCliOptions...)

	return cli.Command{
		Name:   "up",
		Usage:  "Bring the cluster up",
		Action: clusterUpFromCli,
		Flags:  upFlags,
	}
}

func ClusterUp(
	ctx context.Context,
	config *types.KubernetesEngineConfig,
	dockerDialerFactory, localConnDialerFactory tunnel.DialerFactory,
	k8sWrapTransport k8s.WrapTransport,
	local bool, configDir string, updateOnly, disablePortCheck bool) (string, string, string, string, map[string]pki.CertificatePKI, error) {
	log.Infof("Building Kubernetes cluster")
	var APIURL, caCrt, clientCert, clientKey string
	kubeCluster, err := cluster.ParseCluster(ctx, config, clusterFilePath, configDir, dockerDialerFactory, localConnDialerFactory, k8sWrapTransport)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}
	err = kubeCluster.TunnelHosts(ctx, local)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	currentCluster, err := kubeCluster.GetClusterState(ctx)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}
	if !disablePortCheck {
		if err = kubeCluster.CheckClusterPorts(ctx, currentCluster); err != nil {
			return APIURL, caCrt, clientCert, clientKey, nil, err
		}
	}

	err = cluster.SetUpAuthentication(ctx, kubeCluster, currentCluster)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = cluster.ReconcileCluster(ctx, kubeCluster, currentCluster, updateOnly)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = kubeCluster.SetUpHosts(ctx)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	if err := kubeCluster.PrePullK8sImages(ctx); err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = kubeCluster.DeployControlPlane(ctx)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	// Apply Authz configuration after deploying controlplane
	err = cluster.ApplyAuthzResources(ctx, kubeCluster.KubernetesEngineConfig, clusterFilePath, configDir, k8sWrapTransport)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = kubeCluster.SaveClusterState(ctx, config)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = kubeCluster.DeployWorkerPlane(ctx)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	if err = kubeCluster.CleanDeadLogs(ctx); err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = kubeCluster.SyncLabelsAndTaints(ctx)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}

	err = cluster.ConfigureCluster(ctx, kubeCluster.KubernetesEngineConfig, kubeCluster.Certificates, clusterFilePath, configDir, k8sWrapTransport, false)
	if err != nil {
		return APIURL, caCrt, clientCert, clientKey, nil, err
	}
	if len(kubeCluster.ControlPlaneHosts) > 0 {
		APIURL = fmt.Sprintf("https://" + kubeCluster.ControlPlaneHosts[0].Address + ":6443")
		clientCert = string(cert.EncodeCertPEM(kubeCluster.Certificates[pki.KubeAdminCertName].Certificate))
		clientKey = string(cert.EncodePrivateKeyPEM(kubeCluster.Certificates[pki.KubeAdminCertName].Key))
	}
	caCrt = string(cert.EncodeCertPEM(kubeCluster.Certificates[pki.CACertName].Certificate))

	log.Infof("Finished building Kubernetes cluster successfully")
	return APIURL, caCrt, clientCert, clientKey, kubeCluster.Certificates, nil
}

func clusterUpFromCli(ctx *cli.Context) error {
	if ctx.Bool("local") {
		return clusterUpLocal(ctx)
	}
	clusterFile, filePath, err := resolveClusterFile(ctx)
	if err != nil {
		return fmt.Errorf("Failed to resolve cluster file: %v", err)
	}
	clusterFilePath = filePath

	config, err := cluster.ParseConfig(clusterFile)
	if err != nil {
		return fmt.Errorf("Failed to parse cluster file: %v", err)
	}

	config, err = setOptionsFromCLI(ctx, config)
	if err != nil {
		return err
	}
	updateOnly := ctx.Bool("update-only")
	disablePortCheck := ctx.Bool("disable-port-check")

	_, _, _, _, _, err = ClusterUp(context.Background(), config, nil, nil, nil, false, "", updateOnly, disablePortCheck)
	return err
}

func clusterUpLocal(ctx *cli.Context) error {
	var config *types.KubernetesEngineConfig
	clusterFile, filePath, err := resolveClusterFile(ctx)
	if err != nil {
		log.Infof("Failed to resolve cluster file, using default cluster instead")
		config = cluster.GetLocalConfig()
	} else {
		clusterFilePath = filePath
		config, err = cluster.ParseConfig(clusterFile)
		if err != nil {
			return fmt.Errorf("Failed to parse cluster file: %v", err)
		}
		config.Nodes = []types.ConfigNode{*cluster.GetLocalNodeConfig()}
	}
	_, _, _, _, _, err = ClusterUp(context.Background(), config, nil, tunnel.LocalHealthcheckFactory, nil, true, "", false, false)
	return err
}
