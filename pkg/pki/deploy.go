package pki

import (
	"context"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"k8s.io/client-go/util/cert"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/docker"
	"yunion.io/x/yke/pkg/hosts"
	ytypes "yunion.io/x/yke/pkg/types"
)

const (
	StateDeployerContainerName = "cluster-state-deployer"
)

func DeployCertificatesOnPlaneHost(ctx context.Context, host *hosts.Host, keConfig ytypes.KubernetesEngineConfig, crtMap map[string]CertificatePKI, certDownloaderImage string, prsMap map[string]ytypes.PrivateRegistry, rotateCerts bool) error {
	crtBundle := GenerateNodeCerts(ctx, keConfig, host.Address, crtMap)
	env := []string{}
	for _, crt := range crtBundle {
		env = append(env, crt.ToEnv()...)
	}
	if rotateCerts {
		env = append(env, "FORCE_DEPLOY=true")
	}
	return doRunDeployer(ctx, host, env, certDownloaderImage, prsMap)
}

func DeployStateOnPlaneHost(ctx context.Context, host *hosts.Host, stateDownloaderImage string, prsMap map[string]ytypes.PrivateRegistry, clusterState string) error {
	// remove existing container. Only way it's still here is if previous deployment failed
	if err := docker.DoRemoveContainer(ctx, host.DClient, StateDeployerContainerName, host.Address); err != nil {
		return err
	}
	containerEnv := []string{ClusterStateEnv + "=" + clusterState}
	ClusterStateFilePath := path.Join(host.PrefixPath, TempCertPath, ClusterStateFile)
	imageCfg := &container.Config{
		Image: stateDownloaderImage,
		Cmd: []string{
			"sh",
			"-c",
			fmt.Sprintf("t=$(mktemp); echo -e \"$%s\" > $t && mv $t %s && chmod 644 %s", ClusterStateEnv, ClusterStateFilePath,
				ClusterStateFilePath),
		},
		Env: containerEnv,
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/etc/kubernetes:z", path.Join(host.PrefixPath, "/etc/kubernetes")),
		},
		Privileged: true,
	}
	if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, StateDeployerContainerName, host.Address, "state", prsMap); err != nil {
		return err
	}
	if err := docker.DoRemoveContainer(ctx, host.DClient, StateDeployerContainerName, host.Address); err != nil {
		return err
	}
	log.Debugf("[state] Successfully started state deployer container on node [%s]", host.Address)
	return nil
}

func doRunDeployer(ctx context.Context, host *hosts.Host, containerEnv []string, certDownloaderImage string, prsMap map[string]ytypes.PrivateRegistry) error {
	// remove existing container. Only way it's still here is if previous deployment failed
	isRunning := false
	isRunning, err := docker.IsContainerRunning(ctx, host.DClient, host.Address, CrtDownloaderContainer, true)
	if err != nil {
		return err
	}
	if isRunning {
		if err := docker.RemoveContainer(ctx, host.DClient, host.Address, CrtDownloaderContainer); err != nil {
			return err
		}
	}
	if err := docker.UseLocalOrPull(ctx, host.DClient, host.Address, certDownloaderImage, CertificatesServiceName, prsMap); err != nil {
		return err
	}
	imageCfg := &container.Config{
		Image: certDownloaderImage,
		Cmd:   []string{"cert-deployer"},
		Env:   containerEnv,
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/etc/kubernetes:z", path.Join(host.PrefixPath, "/etc/kubernetes")),
		},
		Privileged: true,
	}
	resp, err := host.DClient.ContainerCreate(ctx, imageCfg, hostCfg, nil, CrtDownloaderContainer)
	if err != nil {
		return fmt.Errorf("Failed to create Certificates deployer container on host [%s]: %v", host.Address, err)
	}

	if err := host.DClient.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("Failed to start Certificates deployer container on host [%s]: %v", host.Address, err)
	}
	log.Debugf("[certificates] Successfully started Certificate deployer container: %s", resp.ID)
	for {
		isDeployerRunning, err := docker.IsContainerRunning(ctx, host.DClient, host.Address, CrtDownloaderContainer, false)
		if err != nil {
			return err
		}
		if isDeployerRunning {
			time.Sleep(5 * time.Second)
			continue
		}
		if err := host.DClient.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{}); err != nil {
			return fmt.Errorf("Failed to delete Certificates deployer container on host [%s]: %v", host.Address, err)
		}
		return nil
	}
}

func DeployAdminConfig(ctx context.Context, kubeConfig, localConfigPath string) error {
	if len(kubeConfig) == 0 {
		return nil
	}
	log.Debugf("Deploying admin Kubeconfig locally: %s", kubeConfig)
	err := ioutil.WriteFile(localConfigPath, []byte(kubeConfig), 0640)
	if err != nil {
		return fmt.Errorf("Failed to create local admin kubeconfig file: %v", err)
	}
	log.Infof("Successfully Deployed local admin kubeconfig at [%s]", localConfigPath)
	return nil
}

func RemoveAdminConfig(ctx context.Context, localConfigPath string) {
	log.Infof("Removing local admin Kubeconfig: %s", localConfigPath)
	if err := os.Remove(localConfigPath); err != nil {
		log.Warningf("Failed to remove local admin Kubeconfig file: %v", err)
		return
	}
	log.Infof("Local admin Kubeconfig removed successfully")
}

func DeployCertificatesOnHost(ctx context.Context, host *hosts.Host, crtMap map[string]CertificatePKI, certDownloaderImage, certPath string, prsMap map[string]ytypes.PrivateRegistry) error {
	env := []string{
		"CRTS_DEPLOY_PATH=" + certPath,
	}
	for _, crt := range crtMap {

		env = append(env, crt.ToEnv()...)
	}
	return doRunDeployer(ctx, host, env, certDownloaderImage, prsMap)
}

func FetchCertificatesFromHost(ctx context.Context, extraHosts []*hosts.Host, host *hosts.Host, image, localConfigPath string, prsMap map[string]ytypes.PrivateRegistry) (map[string]CertificatePKI, error) {
	// rebuilding the certificates. This should look better after refactoring pki
	tmpCerts := make(map[string]CertificatePKI)

	crtList := map[string]bool{
		CACertName:                 false,
		KubeAPICertName:            false,
		KubeControllerCertName:     true,
		KubeSchedulerCertName:      true,
		KubeProxyCertName:          true,
		KubeNodeCertName:           true,
		KubeAdminCertName:          false,
		RequestHeaderCACertName:    false,
		APIProxyClientCertName:     false,
		ServiceAccountTokenKeyName: false,
	}

	for _, etcdHost := range extraHosts {
		// Fetch etcd certificates
		crtList[GetEtcdCrtName(etcdHost.InternalAddress)] = false
	}

	for certName, config := range crtList {
		certificate := CertificatePKI{}
		crt, err := FetchFileFromHost(ctx, GetCertTempPath(certName), image, host, prsMap, CertFetcherContainer, "certificates")
		// I will only exit with an error if it's not a not-found-error and this is not an etcd certificate
		if err != nil && (!strings.HasPrefix(certName, "kube-etcd") &&
			!strings.Contains(certName, APIProxyClientCertName) &&
			!strings.Contains(certName, RequestHeaderCACertName) &&
			!strings.Contains(certName, ServiceAccountTokenKeyName)) {
			// IsErrNotFound doesn't catch this because it's a custom error
			if isFileNotFoundErr(err) {
				return nil, nil
			}
			return nil, err
		}
		// If I can't find an etcd or api aggregator cert, I will not fail and will create it later
		if crt == "" && (strings.HasPrefix(certName, "kube-etcd") ||
			strings.Contains(certName, APIProxyClientCertName) ||
			strings.Contains(certName, RequestHeaderCACertName) ||
			strings.Contains(certName, ServiceAccountTokenKeyName)) {
			tmpCerts[certName] = CertificatePKI{}
			continue
		}
		key, err := FetchFileFromHost(ctx, GetKeyTempPath(certName), image, host, prsMap, CertFetcherContainer, "certificate")

		if config {
			config, err := FetchFileFromHost(ctx, GetConfigTempPath(certName), image, host, prsMap, CertFetcherContainer, "certificate")
			if err != nil {
				return nil, err
			}
			certificate.Config = config
		}
		parsedCert, err := cert.ParseCertsPEM([]byte(crt))
		if err != nil {
			return nil, err
		}
		parsedKey, err := cert.ParsePrivateKeyPEM([]byte(key))
		if err != nil {
			return nil, err
		}
		certificate.Certificate = parsedCert[0]
		certificate.Key = parsedKey.(*rsa.PrivateKey)
		tmpCerts[certName] = certificate
		log.Debugf("[certificates] Recovered certificate: %s", certName)
	}

	if err := docker.RemoveContainer(ctx, host.DClient, host.Address, CertFetcherContainer); err != nil {
		return nil, err
	}
	return populateCertMap(tmpCerts, localConfigPath, extraHosts), nil
}

func FetchFileFromHost(ctx context.Context, filePath, image string, host *hosts.Host, prsMap map[string]ytypes.PrivateRegistry, containerName, state string) (string, error) {

	imageCfg := &container.Config{
		Image: image,
	}
	hostCfg := &container.HostConfig{
		Binds: []string{
			fmt.Sprintf("%s:/etc/kubernetes:z", path.Join(host.PrefixPath, "/etc/kubernetes")),
		},
		Privileged: true,
	}
	isRunning, err := docker.IsContainerRunning(ctx, host.DClient, host.Address, containerName, true)
	if err != nil {
		return "", err
	}
	if !isRunning {
		if err := docker.DoRunContainer(ctx, host.DClient, imageCfg, hostCfg, containerName, host.Address, state, prsMap); err != nil {
			return "", err
		}
	}
	file, err := docker.ReadFileFromContainer(ctx, host.DClient, host.Address, containerName, filePath)
	if err != nil {
		return "", err
	}

	return file, nil
}
