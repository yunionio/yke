package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/util/cert"

	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/pki"
	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	HealthzAddress   = "localhost"
	HealthzEndpoint  = "/healthz"
	HTTPProtoPrefix  = "http://"
	HTTPSProtoPrefix = "https://"
)

func runHealthcheck(ctx context.Context, host *hosts.Host, serviceName string, localConnDialerFactory tunnel.DialerFactory, url string, certMap map[string]pki.CertificatePKI) error {
	log.Infof("[healthcheck] Start Healthcheck on service [%s] on host [%s]", serviceName, host.Address)
	var x509Pair tls.Certificate

	port, err := getPortFromURL(url)
	if err != nil {
		return err
	}
	if serviceName == KubeletContainerName {
		certificate := cert.EncodeCertPEM(certMap[pki.KubeNodeCertName].Certificate)
		key := cert.EncodePrivateKeyPEM(certMap[pki.KubeNodeCertName].Key)
		x509Pair, err = tls.X509KeyPair(certificate, key)
		if err != nil {
			return err
		}
	}
	client, err := getHealthCheckHTTPClient(host, port, localConnDialerFactory, &x509Pair)
	if err != nil {
		return fmt.Errorf("Failed to initiate new HTTP client for service [%s] for host [%s]", serviceName, host.Address)
	}
	for retries := 0; retries < 10; retries++ {
		if err = getHealthz(client, serviceName, host.Address, url); err != nil {
			log.Debugf("[healthcheck] %v", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Infof("[healthcheck] service [%s] on host [%s] is healthy", serviceName, host.Address)
		return nil
	}
	return fmt.Errorf("Failed to verify healthcheck: %v", err)
}

func getHealthCheckHTTPClient(host *hosts.Host, port int, localConnDialerFactory tunnel.DialerFactory, x509KeyPair *tls.Certificate) (*http.Client, error) {
	host.LocalConnPort = port
	var factory tunnel.DialerFactory
	if localConnDialerFactory == nil {
		factory = tunnel.LocalConnFactory
	} else {
		factory = localConnDialerFactory
	}
	dialer, err := factory(host.TunnelHostConfig())
	if err != nil {
		return nil, fmt.Errorf("Failed to create a dialer for host [%s]: %v", host.Address, err)
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if x509KeyPair != nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{*x509KeyPair},
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			Dial:            dialer,
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func getHealthz(client *http.Client, serviceName, hostAddress, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("Failed to check %s for service [%s] on host [%s]: %v", url, serviceName, hostAddress, err)
	}
	if resp.StatusCode != http.StatusOK {
		statusBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Service [%s] is not healthy on host [%s]. Response code: [%d], response body: %s", serviceName, hostAddress, resp.StatusCode, statusBody)
	}
	return nil
}

func getPortFromURL(url string) (int, error) {
	port := strings.Split(strings.Split(url, ":")[2], "/")[0]
	intPort, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	return intPort, nil
}
