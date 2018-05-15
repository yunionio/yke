package cluster

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"

	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/k8s"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	KubeAdminConfigDeployer = "kubeadmin-config-deployer"
	KubeAdminConfigPath     = "/etc/kubernetes/kube_config_cluster.yml"
	KubeAdminServiceName    = "kubeadmin"
	KubeAdminConfigEnv      = "YKE_KUBEADMIN_CONFIG"
)

func SetUpAuthentication(ctx context.Context, kubeCluster, currentCluster *Cluster) error {
	if kubeCluster.Authentication.Strategy == X509AuthenticationProvider {
		var err error
		if currentCluster != nil {
			kubeCluster.Certificates = currentCluster.Certificates
		} else {
			var backupHost *hosts.Host
			if len(kubeCluster.Services.Etcd.ExternalURLs) > 0 {
				backupHost = kubeCluster.ControlPlaneHosts[0]
			} else {
				backupHost = kubeCluster.EtcdHosts[0]
			}
			log.Infof("[certificates] Attempting to recover certificates from backup on host [%s]", backupHost.Address)
			kubeCluster.Certificates, err = pki.FetchCertificatesFromHost(ctx, kubeCluster.EtcdHosts, backupHost, kubeCluster.SystemImages.Alpine, kubeCluster.LocalKubeConfigPath, kubeCluster.PrivateRegistriesMap)
			if err != nil {
				return err
			}
			if kubeCluster.Certificates != nil {
				log.Infof("[certificates] Certificate backup found on host [%s]", backupHost.Address)
				// this is the case of adding controlplane node on empty cluster with only etcd nodes
				if kubeCluster.Certificates[pki.KubeAdminCertName].Config == "" && len(kubeCluster.ControlPlaneHosts) > 0 {
					if err := rebuildLocalAdminConfig(ctx, kubeCluster); err != nil {
						return err
					}
					kubeCluster.Certificates, err = regenerateAPICertificate(kubeCluster, kubeCluster.Certificates)
					if err != nil {
						return fmt.Errorf("Failed to regenerate KubeAPI certificate %v", err)
					}
				}
				return nil
			}
			log.Infof("[certificates] No Certificate backup found on host [%s]", backupHost.Address)

			kubeCluster.Certificates, err = pki.GenerateKECerts(ctx, kubeCluster.KubernetesEngineConfig, kubeCluster.LocalKubeConfigPath, "")
			if err != nil {
				return fmt.Errorf("Failed to generate Kubernetes certificates: %v", err)
			}
			log.Infof("[certificates] Temporarily saving certs to control host [%s]", backupHost.Address)
			if err := pki.DeployCertificatesOnHost(ctx, backupHost, kubeCluster.Certificates, kubeCluster.SystemImages.CertDownloader, pki.TempCertPath, kubeCluster.PrivateRegistriesMap); err != nil {
				return err
			}
			log.Infof("[certificates] Saved certs to control host [%s]", backupHost.Address)
		}
	}
	return nil
}

func regenerateAPICertificate(c *Cluster, certificates map[string]pki.CertificatePKI) (map[string]pki.CertificatePKI, error) {
	log.Debugf("[certificates] Regenerating kubeAPI certificate")
	kubeAPIAltNames := pki.GetAltNames(c.ControlPlaneHosts, c.ClusterDomain, c.KubernetesServiceIP, c.Authentication.SANs)
	caCrt := certificates[pki.CACertName].Certificate
	caKey := certificates[pki.CACertName].Key
	kubeAPIKey := certificates[pki.KubeAPICertName].Key
	kubeAPICert, _, err := pki.GenerateSignedCertAndKey(caCrt, caKey, true, pki.KubeAPICertName, kubeAPIAltNames, kubeAPIKey, nil)
	if err != nil {
		return nil, err
	}
	certificates[pki.KubeAPICertName] = pki.ToCertObject(pki.KubeAPICertName, "", "", kubeAPICert, kubeAPIKey)
	return certificates, nil
}

func getClusterCerts(ctx context.Context, kubeClient *kubernetes.Clientset, etcdHosts []*hosts.Host) (map[string]pki.CertificatePKI, error) {
	log.Infof("[certificates] Getting Cluster certificates from Kubernetes")
	certificatesNames := []string{
		pki.CACertName,
		pki.KubeAPICertName,
		pki.KubeNodeCertName,
		pki.KubeProxyCertName,
		pki.KubeControllerCertName,
		pki.KubeSchedulerCertName,
		pki.KubeAdminCertName,
	}

	for _, etcdHost := range etcdHosts {
		etcdName := pki.GetEtcdCrtName(etcdHost.InternalAddress)
		certificatesNames = append(certificatesNames, etcdName)
	}

	certMap := make(map[string]pki.CertificatePKI)
	for _, certName := range certificatesNames {
		secret, err := k8s.GetSecret(kubeClient, certName)
		if err != nil {
			return nil, err
		}
		secretCert, _ := cert.ParseCertsPEM(secret.Data["Certificate"])
		secretKey, _ := cert.ParsePrivateKeyPEM(secret.Data["Key"])
		secretConfig := string(secret.Data["Config"])
		certMap[certName] = pki.CertificatePKI{
			Certificate:   secretCert[0],
			Key:           secretKey.(*rsa.PrivateKey),
			Config:        secretConfig,
			EnvName:       string(secret.Data["EnvName"]),
			ConfigEnvName: string(secret.Data["ConfigEnvName"]),
			KeyEnvName:    string(secret.Data["KeyEnvName"]),
			Path:          string(secret.Data["Path"]),
			KeyPath:       string(secret.Data["KeyPath"]),
			ConfigPath:    string(secret.Data["ConfigPath"]),
		}
	}
	log.Infof("[certificates] Successfully fetched Cluster certificates from Kubernetes")
	return certMap, nil
}

func saveClusterCerts(ctx context.Context, kubeClient *kubernetes.Clientset, crts map[string]pki.CertificatePKI) error {
	log.Infof("[certificates] Save kubernetes certificates as secrets")
	var errgrp errgroup.Group
	for crtName, crt := range crts {
		name := crtName
		certificate := crt
		errgrp.Go(func() error {
			return saveCertToKubernetes(kubeClient, name, certificate)
		})
	}
	if err := errgrp.Wait(); err != nil {
		return err

	}
	log.Infof("[certificates] Successfully saved certificates as kubernetes secret [%s]", pki.CertificatesSecretName)
	return nil
}

func saveCertToKubernetes(kubeClient *kubernetes.Clientset, crtName string, crt pki.CertificatePKI) error {
	log.Debugf("[certificates] Saving certificate [%s] to kubernetes", crtName)
	timeout := make(chan bool, 1)

	// build secret Data
	secretData := make(map[string][]byte)
	if crt.Certificate != nil {
		secretData["Certificate"] = cert.EncodeCertPEM(crt.Certificate)
		secretData["EnvName"] = []byte(crt.EnvName)
		secretData["Path"] = []byte(crt.Path)
	}
	if crt.Key != nil {
		secretData["Key"] = cert.EncodePrivateKeyPEM(crt.Key)
		secretData["KeyEnvName"] = []byte(crt.KeyEnvName)
		secretData["KeyPath"] = []byte(crt.KeyPath)
	}
	if len(crt.Config) > 0 {
		secretData["ConfigEnvName"] = []byte(crt.ConfigEnvName)
		secretData["Config"] = []byte(crt.Config)
		secretData["ConfigPath"] = []byte(crt.ConfigPath)
	}
	go func() {
		for {
			err := k8s.UpdateSecret(kubeClient, secretData, crtName)
			if err != nil {
				time.Sleep(time.Second * 5)
				continue
			}
			timeout <- true
			break
		}
	}()
	select {
	case <-timeout:
		return nil
	case <-time.After(time.Second * KubernetesClientTimeOut):
		return fmt.Errorf("[certificates] Timeout waiting for kubernetes to be ready")
	}
}

func deployAdminConfig(ctx context.Context, uniqueHosts []*hosts.Host, kubeAdminConfig string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	if len(kubeAdminConfig) == 0 {
		return nil
	}
	for _, host := range uniqueHosts {
		log.Debugf("Deploying admin kubeconfig to host [%s]", host.Address)
		if err := doDeployAdminConfig(ctx, host, kubeAdminConfig, alpineImage, prsMap); err != nil {
			return fmt.Errorf("Failed to deploy admin kubeconfig on node [%s]: %v", host.Address, err)
		}
	}
	return nil
}

func doDeployAdminConfig(ctx context.Context, host *hosts.Host, kubeAdminConfig string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	return host.WriteHostFile(ctx, KubeAdminConfigDeployer, KubeAdminConfigPath, kubeAdminConfig, alpineImage, prsMap)
}
