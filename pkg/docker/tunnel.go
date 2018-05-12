package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"

	"yunion.io/yke/pkg/tunnel"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	DockerAPIVersion  = "1.24"
	DockerRegistryURL = "docker.io"
)

var K8sDockerVersions = map[string][]string{
	"1.8":  {"1.11.x", "1.12.x", "1.13.x", "17.03.x"},
	"1.9":  {"1.11.x", "1.12.x", "1.13.x", "17.03.x"},
	"1.10": {"1.11.x", "1.12.x", "1.13.x", "17.03.x"},
}

func TunnelUpClient(ctx context.Context, h tunnel.HostConfig, dialerFactory tunnel.DialerFactory) (*client.Client, error) {
	log.Infof("[dialer] Setup tunnel for host [%s]", h.Address)
	httpClient, err := tunnel.NewHTTPClient(h, dialerFactory)
	if err != nil {
		return nil, fmt.Errorf("Can't establish dialer connection: %v", err)
	}
	log.Infof("Connecting to Docker API for host [%s]", h.Address)
	dClient, err := client.NewClient("unix:///var/run/docker.sock", DockerAPIVersion, httpClient, nil)
	if err != nil {
		return nil, fmt.Errorf("Can't initiate docker client: %v", err)
	}
	return dClient, nil
}

func TunnelUpLocalClient(ctx context.Context, h tunnel.HostConfig) (*client.Client, error) {
	log.Debugf("Connecting to Docker API for host [%s]", h.Address)
	dClient, err := client.NewEnvClient()
	if err != nil {
		return nil, fmt.Errorf("Can't initiate local docker client: %v", err)
	}
	return dClient, nil
}

func convertToSemver(version string) (*semver.Version, error) {
	compVersion := strings.SplitN(version, ".", 3)
	if len(compVersion) != 3 {
		return nil, fmt.Errorf("The default version is not correct")
	}
	compVersion[2] = "0"
	return semver.NewVersion(strings.Join(compVersion, "."))
}

func IsSupportedDockerVersion(info types.Info, K8sVersion string) (bool, error) {
	dockerVersion, err := semver.NewVersion(info.ServerVersion)
	if err != nil {
		return false, err
	}
	for _, DockerVersion := range K8sDockerVersions[K8sVersion] {
		supportedDockerVersion, err := convertToSemver(DockerVersion)
		if err != nil {
			return false, err
		}
		if dockerVersion.Major == supportedDockerVersion.Major && dockerVersion.Minor == supportedDockerVersion.Minor {
			return true, nil
		}
	}
	return false, nil
}
