package hosts

import (
	"os"
	"io/ioutil"
	"context"
	"fmt"
	"net"
	"path/filepath"

	"github.com/docker/docker/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"yunion.io/x/log"

	"yunion.io/yke/pkg/docker"
	"yunion.io/yke/pkg/tunnel"
)

const (
	DockerAPIVersion = "1.24"
	K8sVersion       = "1.8"
)

func (h *Host) TunnelUp(ctx context.Context, dailerFactory DialerFactory, clusterPrefixPath string) error {
	if h.DClient != nil {
		return nil
	}
	log.Infof("[dialer] Setup tunnel for host [%s]", h.Address)
	httpClient, err := h.newHTTPClient(dailerFactory)
	if err != nil {
		return fmt.Errorf("Can't establish dialer connection: %v", err)
	}
	// set Docker client
	log.Debugf("Connecting to Docker API for host [%s]", h.Address)
	h.DClient, err = client.NewClient("unix:///var/run/docker.sock", DockerAPIVersion, httpClient, nil)
	if err != nil {
		return fmt.Errorf("Can't initiate NewClient: %v", err)
	}
	if err := checkDockerVersion(ctx, h); err != nil {
		return err
	}
	h.PrefixPath = GetPrefixPath(h.DockerInfo.OperatingSystem, clusterPrefixPath)
	return nil
}

func (h *Host) TunnelUpLocal(ctx context.Context) error {
	var err error
	if h.DClient != nil {
		return nil
	}
	// set Docker client
	log.Debugf("Connecting to Docker API for host [%s]", h.Address)
	h.DClient, err = client.NewEnvClient()
	if err != nil {
		return fmt.Errorf("Can't initiate NewClient: %v",e rr)
	}
	return checkDockerVersion(ctx, h)
}

func checkDockerVersion(ctx context.Context, h *Host) error {
	info, err := h.DClient.Info(ctx)
	if err != nil {
		return fmt.Errorf("Can't retrieve Docker Info: %v", err)
	}
	log.Debugf("Docker Info found: %#v", info)
	h.DockerInfo = info
	isvalid, err := docker.IsSupportedDockerVersion(info, K8sVersion)
	if err != nil {
		return fmt.Errorf("Error while determining supported Docker version [%s]: %v", info.ServerVersion, err)
	}

	if !isvalid && !h.IgnoreDockerVersion {
		return fmt.Errorf("Unsupported Docker version found [%s], supported versions are %v", info.ServerVersion, docker.K8sDockerVersions[K8sVersion])
	} else if !isvalid {
		log.Warningf("Unsupported Docker version found [%s], supported versions are %v", info.ServerVersion, docker.K8sDockerVersions[K8sVersion])
	}
	return nil
}

func parsePrivateKey(keyBuff string) (ssh.Signer, error) {
	return ssh.ParsePrivateKey([]byte(keyBuff))
}

func getSSHConfig(username, sshPrivateKeyString string, useAgentAuth bool) (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User: username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Kind of a double check now
	if useAgentAuth {
		if sshAgentSock := os.Getenv("SSH_AUTH_SOCK"); sshAgentSock != "" {
			sshAgent, err := net.Dial("unix", sshAgentSock)
			if err != nil {
				return config, fmt.Errorf("Cannot connect to SSH Auth socket %q: %s", sshAgentSock, err)
			}

			config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers))
			log.Debugf("using %q SSH_AUTH_SOCK", sshAgentSock)
			return config, nil
		}
	}

	signer, err := parsePrivateKey(sshPrivateKeyString)
	if err != nil {
		return config, err
	}
	config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	return config, nil
}

func privateKeyPath(sshKeyPath string) (string, error) {
	if sshKeyPath[:2] == "~/" {
		sshKeyPath = filepath.Join(userHome(), sshKeyPath[2:])
	}
	buff, err := ioutil.ReadFile(sshKeyPath)
	if err != nil {
		return "", fmt.Errorf("Error while reading SSH key file: %v", err)
	}
	return string(buff), nil
}

func userHome() string {
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	homeDrive := os.Getenv("HOMEDRIVE")
	homePath := os.Getenv("HOMEPATH")
	if homeDrive != "" && homePath != "" {
		return homeDrive + homePath
	}
	return os.Getenv("USERPROFILE")
}