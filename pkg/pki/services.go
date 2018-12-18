package pki

import (
	"context"
	"crypto/rsa"
	"fmt"
	"reflect"

	"k8s.io/client-go/util/cert"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/types"
)

func GenerateKubeAPICertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate API certificate and key
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	kubernetesServiceIP, err := GetKubernetesServiceIP(keConfig.Services.KubeAPI.ServiceClusterIPRange)
	if err != nil {
		return fmt.Errorf("Failed to get Kubernetes Service IP: %v", err)
	}
	clusterDomain := keConfig.Services.Kubelet.ClusterDomain
	cpHosts := hosts.NodesToHosts(keConfig.Nodes, controlRole)
	kubeAPIAltNames := GetAltNames(cpHosts, clusterDomain, kubernetesServiceIP, keConfig.Authentication.SANs)
	kubeAPICert := certs[KubeAPICertName].Certificate
	if kubeAPICert != nil &&
		reflect.DeepEqual(kubeAPIAltNames.DNSNames, kubeAPICert.DNSNames) &&
		deepEqualIPsAltNames(kubeAPIAltNames.IPs, kubeAPICert.IPAddresses) {
		return nil
	}
	log.Infof("[certificates] Generating Kubernetes API server certificates")
	kubeAPICrt, kubeAPIKey, err := GenerateSignedCertAndKey(caCrt, caKey, true, KubeAPICertName, kubeAPIAltNames, certs[KubeAPICertName].Key, nil)
	if err != nil {
		return err
	}
	certs[KubeAPICertName] = ToCertObject(KubeAPICertName, "", "", kubeAPICrt, kubeAPIKey)
	// handle service account tokens in old clusters
	apiCert := certs[KubeAPICertName]
	if certs[ServiceAccountTokenKeyName].Key == nil {
		log.Infof("[certificates] Generating Service account token key")
		certs[ServiceAccountTokenKeyName] = ToCertObject(ServiceAccountTokenKeyName, ServiceAccountTokenKeyName, "", apiCert.Certificate, apiCert.Key)
	}
	return nil
}

func GenerateKubeControllerCertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate Kube controller-manager certificate and key
	log.Infof("[certificates] Generating Kube Controller certificates")
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	kubeControllerCrt, kubeControllerKey, err := GenerateSignedCertAndKey(caCrt, caKey, false, getDefaultCN(KubeControllerCertName), nil, nil, nil)
	if err != nil {
		return err
	}
	certs[KubeControllerCertName] = ToCertObject(KubeControllerCertName, "", "", kubeControllerCrt, kubeControllerKey)
	return nil
}

func GenerateKubeSchedulerCertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate Kube scheduler certificate and key
	log.Infof("[certificates] Generating Kube Scheduler certificates")
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	kubeSchedulerCrt, kubeSchedulerKey, err := GenerateSignedCertAndKey(caCrt, caKey, false, getDefaultCN(KubeSchedulerCertName), nil, nil, nil)
	if err != nil {
		return err
	}
	certs[KubeSchedulerCertName] = ToCertObject(KubeSchedulerCertName, "", "", kubeSchedulerCrt, kubeSchedulerKey)
	return nil
}

func GenerateKubeProxyCertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate Kube Proxy certificate and key
	log.Infof("[certificates] Generating Kube Proxy certificates")
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	kubeProxyCrt, kubeProxyKey, err := GenerateSignedCertAndKey(caCrt, caKey, false, getDefaultCN(KubeProxyCertName), nil, nil, nil)
	if err != nil {
		return err
	}
	certs[KubeProxyCertName] = ToCertObject(KubeProxyCertName, "", "", kubeProxyCrt, kubeProxyKey)
	return nil
}

func GenerateKubeNodeCertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate kubelet certificate
	log.Infof("[certificates] Generating Node certificate")
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	nodeCrt, nodeKey, err := GenerateSignedCertAndKey(caCrt, caKey, false, KubeNodeCommonName, nil, nil, []string{KubeNodeOrganizationName})
	if err != nil {
		return err
	}
	certs[KubeNodeCertName] = ToCertObject(KubeNodeCertName, KubeNodeCommonName, KubeNodeOrganizationName, nodeCrt, nodeKey)
	return nil
}

func GenerateKubeAdminCertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate Admin certificate and key
	log.Infof("[certificates] Generating admin certificates and kubeconfig")
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	cpHosts := hosts.NodesToHosts(keConfig.Nodes, controlRole)
	if len(configPath) == 0 {
		configPath = ClusterConfig
	}
	localKubeConfigPath := GetLocalKubeConfig(configPath, configDir)
	kubeAdminCrt, kubeAdminKey, err := GenerateSignedCertAndKey(caCrt, caKey, false, KubeAdminCertName, nil, nil, []string{KubeAdminOrganizationName})
	if err != nil {
		return err
	}
	kubeAdminCertObj := ToCertObject(KubeAdminCertName, KubeAdminCertName, KubeAdminOrganizationName, kubeAdminCrt, kubeAdminKey)
	if len(cpHosts) > 0 {
		kubeAdminConfig := GetKubeConfigX509WithData(
			"https://"+cpHosts[0].Address+":6443",
			keConfig.ClusterName,
			KubeAdminCertName,
			string(cert.EncodeCertPEM(caCrt)),
			string(cert.EncodeCertPEM(kubeAdminCrt)),
			string(cert.EncodePrivateKeyPEM(kubeAdminKey)))
		kubeAdminCertObj.Config = kubeAdminConfig
		kubeAdminCertObj.ConfigPath = localKubeConfigPath
	} else {
		kubeAdminCertObj.Config = ""
	}
	certs[KubeAdminCertName] = kubeAdminCertObj
	return nil
}

func GenerateAPIProxyClientCertificate(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	//generate API server proxy client key and certs
	log.Infof("[certificates] Generating Kubernetes API server proxy client certificates")
	caCrt := certs[RequestHeaderCACertName].Certificate
	caKey := certs[RequestHeaderCACertName].Key
	apiserverProxyClientCrt, apiserverProxyClientKey, err := GenerateSignedCertAndKey(caCrt, caKey, true, APIProxyClientCertName, nil, nil, nil)
	if err != nil {
		return err
	}
	certs[APIProxyClientCertName] = ToCertObject(APIProxyClientCertName, "", "", apiserverProxyClientCrt, apiserverProxyClientKey)
	return nil
}

func GenerateExternalEtcdCertificates(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	clientCert, err := cert.ParseCertsPEM([]byte(keConfig.Services.Etcd.Cert))
	if err != nil {
		return err
	}
	clientKey, err := cert.ParsePrivateKeyPEM([]byte(keConfig.Services.Etcd.Key))
	if err != nil {
		return err
	}
	certs[EtcdClientCertName] = ToCertObject(EtcdClientCertName, "", "", clientCert[0], clientKey.(*rsa.PrivateKey))

	caCert, err := cert.ParseCertsPEM([]byte(keConfig.Services.Etcd.CACert))
	if err != nil {
		return err
	}
	certs[EtcdClientCACertName] = ToCertObject(EtcdClientCACertName, "", "", caCert[0], nil)
	return nil
}

func GenerateEtcdCertificates(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	kubernetesServiceIP, err := GetKubernetesServiceIP(keConfig.Services.KubeAPI.ServiceClusterIPRange)
	if err != nil {
		return fmt.Errorf("Failed to get Kubernetes Service IP: %v", err)
	}
	clusterDomain := keConfig.Services.Kubelet.ClusterDomain
	etcdHosts := hosts.NodesToHosts(keConfig.Nodes, etcdRole)
	etcdAltNames := GetAltNames(etcdHosts, clusterDomain, kubernetesServiceIP, []string{})
	for _, host := range etcdHosts {
		log.Infof("[certificates] Generating etcd-%s certificate and key", host.InternalAddress)
		etcdName := GetEtcdCrtName(host.InternalAddress)
		etcdCrt, etcdKey, err := GenerateSignedCertAndKey(caCrt, caKey, true, EtcdCertName, etcdAltNames, nil, nil)
		if err != nil {
			return err
		}
		certs[etcdName] = ToCertObject(etcdName, "", "", etcdCrt, etcdKey)
	}
	return nil
}

func GenerateServiceTokenKey(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	// generate service account token key
	var privateAPIKey *rsa.PrivateKey
	caCrt := certs[CACertName].Certificate
	caKey := certs[CACertName].Key
	// handle rotation on old clusters
	if certs[ServiceAccountTokenKeyName].Key == nil {
		privateAPIKey = certs[KubeAPICertName].Key
	}
	tokenCrt, tokenKey, err := GenerateSignedCertAndKey(caCrt, caKey, false, ServiceAccountTokenKeyName, nil, privateAPIKey, nil)
	if err != nil {
		return fmt.Errorf("Failed to generate private key for service account token: %v", err)
	}
	certs[ServiceAccountTokenKeyName] = ToCertObject(ServiceAccountTokenKeyName, ServiceAccountTokenKeyName, "", tokenCrt, tokenKey)
	return nil
}

func GenerateKECACerts(ctx context.Context, certs map[string]CertificatePKI, configPath, configDir string) error {
	// generate kubernetes CA certificate and key
	log.Infof("[certificates] Generating CA kubernetes certificates")
	caCrt, caKey, err := GenerateCACertAndKey(CACertName, certs[CACertName].Key)
	if err != nil {
		return err
	}
	certs[CACertName] = ToCertObject(CACertName, "", "", caCrt, caKey)

	// generate request header client CA certificate and key
	log.Infof("[certificates] Generating Kubernetes API server aggregation layer requestheader client CA certificates")
	requestHeaderCACrt, requestHeaderCAKey, err := GenerateCACertAndKey(RequestHeaderCACertName, nil)
	if err != nil {
		return err
	}
	certs[RequestHeaderCACertName] = ToCertObject(RequestHeaderCACertName, "", "", requestHeaderCACrt, requestHeaderCAKey)
	return nil
}

func GenerateKEServicesCerts(ctx context.Context, certs map[string]CertificatePKI, keConfig types.KubernetesEngineConfig, configPath, configDir string) error {
	KECerts := []GenFunc{
		GenerateKubeAPICertificate,
		GenerateServiceTokenKey,
		GenerateKubeControllerCertificate,
		GenerateKubeSchedulerCertificate,
		GenerateKubeProxyCertificate,
		GenerateKubeNodeCertificate,
		GenerateKubeAdminCertificate,
		GenerateAPIProxyClientCertificate,
		GenerateEtcdCertificates,
	}
	for _, gen := range KECerts {
		if err := gen(ctx, certs, keConfig, configPath, configDir); err != nil {
			return err
		}
	}
	if len(keConfig.Services.Etcd.ExternalURLs) > 0 {
		return GenerateExternalEtcdCertificates(ctx, certs, keConfig, configPath, configDir)
	}
	return nil
}
