package cluster

import (
	"context"

	ref "github.com/docker/distribution/reference"

	"yunion.io/yke/pkg/services"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	DefaultServiceClusterIPRange = "10.43.0.0/16"
	//DefaultClusterCIDR           = "10.42.0.0/16"
	DefaultClusterCIDR       = "10.43.0.0/16"
	DefaultClusterDNSService = "10.43.0.10"
	DefaultClusterDomain     = "cluster.local"
	DefaultClusterName       = "local"
	DefaultClusterSSHKeyPath = "~/.ssh/id_rsa"

	DefaultK8sVersion = types.K8sV19

	DefaultSSHPort        = "22"
	DefaultDockerSockPath = "/var/run/docker.sock"

	DefaultAuthStrategy      = "x509"
	DefaultAuthorizationMode = "rbac"

	DefaultNetworkPlugin = "yunion"

	DefaultIngressController = "nginx"
)

func setDefaultIfEmptyMapValue(configMap map[string]string, key string, value string) {
	if _, ok := configMap[key]; !ok {
		configMap[key] = value
	}
}

func setDefaultIfEmpty(varName *string, defaultValue string) {
	if len(*varName) == 0 {
		*varName = defaultValue
	}
}

func (c *Cluster) setClusterDefaults(ctx context.Context) {
	if len(c.SSHKeyPath) == 0 {
		c.SSHKeyPath = DefaultClusterSSHKeyPath
	}

	for i, host := range c.Nodes {
		if len(host.InternalAddress) == 0 {
			c.Nodes[i].InternalAddress = c.Nodes[i].Address
		}
		if len(host.HostnameOverride) == 0 {
			// This is a temporary modification
			c.Nodes[i].HostnameOverride = c.Nodes[i].Address
		}
		if len(host.SSHKeyPath) == 0 {
			c.Nodes[i].SSHKeyPath = c.SSHKeyPath
		}
		if len(host.Port) == 0 {
			c.Nodes[i].Port = DefaultSSHPort
		}

		// For now, you can set at the global level only.
		c.Nodes[i].SSHAgentAuth = c.SSHAgentAuth
	}

	if len(c.Authorization.Mode) == 0 {
		c.Authorization.Mode = DefaultAuthorizationMode
	}
	if c.Services.KubeAPI.PodSecurityPolicy && c.Authorization.Mode != services.RBACAuthorizationMode {
		log.Warningf("PodSecurityPolicy can't be enabled with RBAC support disabled")
		c.Services.KubeAPI.PodSecurityPolicy = false
	}
	if len(c.Ingress.Provider) == 0 {
		c.Ingress.Provider = DefaultIngressController
	}
	if len(c.ClusterName) == 0 {
		c.ClusterName = DefaultClusterName
	}

	c.setClusterImageDefaults()
	c.setClusterKubernetesImageVersion(ctx)
	c.setClusterServicesDefaults()
	c.setClusterNetworkDefaults()
}

func (c *Cluster) setClusterKubernetesImageVersion(ctx context.Context) {
	k8sImageNamed, _ := ref.ParseNormalizedNamed(c.SystemImages.Kubernetes)
	// Kubernetes image is already set by c.setClusterImageDefaults(),
	// I will override it here if Version is set.
	var VersionedImageNamed ref.NamedTagged
	if c.Version != "" {
		VersionedImageNamed, _ = ref.WithTag(ref.TrimNamed(k8sImageNamed), c.Version)
		c.SystemImages.Kubernetes = VersionedImageNamed.String()
	}
	normalizedSystemImage, _ := ref.ParseNormalizedNamed(c.SystemImages.Kubernetes)
	if normalizedSystemImage.String() != k8sImageNamed.String() {
		log.Infof("Overrding Kubernetes image [%s] with tag [%s]", VersionedImageNamed.Name(), VersionedImageNamed.Tag())
	}
}

func (c *Cluster) setClusterServicesDefaults() {
	serviceConfigDefaultsMap := map[*string]string{
		&c.Services.KubeAPI.ServiceClusterIPRange:        DefaultServiceClusterIPRange,
		&c.Services.KubeController.ServiceClusterIPRange: DefaultServiceClusterIPRange,
		&c.Services.KubeController.ClusterCIDR:           DefaultClusterCIDR,
		&c.Services.Kubelet.ClusterDNSServer:             DefaultClusterDNSService,
		&c.Services.Kubelet.ClusterDomain:                DefaultClusterDomain,
		&c.Services.Kubelet.InfraContainerImage:          c.SystemImages.PodInfraContainer,
		&c.Authentication.Strategy:                       DefaultAuthStrategy,
		&c.Services.KubeAPI.Image:                        c.SystemImages.Kubernetes,
		&c.Services.Scheduler.Image:                      c.SystemImages.Kubernetes,
		&c.Services.KubeController.Image:                 c.SystemImages.Kubernetes,
		&c.Services.Kubelet.Image:                        c.SystemImages.Kubernetes,
		&c.Services.Kubeproxy.Image:                      c.SystemImages.Kubernetes,
		&c.Services.Etcd.Image:                           c.SystemImages.Etcd,
		&c.Services.YunionWebhookAuth.Image:              c.SystemImages.YunionK8sKeystoneAuth,
	}
	for k, v := range serviceConfigDefaultsMap {
		setDefaultIfEmpty(k, v)
	}
}

func (c *Cluster) setClusterImageDefaults() {
	imageDefaults, ok := types.K8sVersionToSystemImages[c.Version]
	if !ok {
		imageDefaults = types.K8sVersionToSystemImages[DefaultK8sVersion]
	}

	systemImagesDefaultsMap := map[*string]string{
		&c.SystemImages.Alpine:                    imageDefaults.Alpine,
		&c.SystemImages.NginxProxy:                imageDefaults.NginxProxy,
		&c.SystemImages.CertDownloader:            imageDefaults.CertDownloader,
		&c.SystemImages.KubeDNS:                   imageDefaults.KubeDNS,
		&c.SystemImages.KubeDNSSidecar:            imageDefaults.KubeDNSSidecar,
		&c.SystemImages.DNSmasq:                   imageDefaults.DNSmasq,
		&c.SystemImages.KubeDNSAutoscaler:         imageDefaults.KubeDNSAutoscaler,
		&c.SystemImages.KubernetesServicesSidecar: imageDefaults.KubernetesServicesSidecar,
		&c.SystemImages.Etcd:                      imageDefaults.Etcd,
		&c.SystemImages.Kubernetes:                imageDefaults.Kubernetes,
		&c.SystemImages.PodInfraContainer:         imageDefaults.PodInfraContainer,
		&c.SystemImages.YunionCNI:                 imageDefaults.YunionCNI,
		&c.SystemImages.Ingress:                   imageDefaults.Ingress,
		&c.SystemImages.IngressBackend:            imageDefaults.IngressBackend,
		&c.SystemImages.YunionK8sKeystoneAuth:     imageDefaults.YunionK8sKeystoneAuth,
	}

	for k, v := range systemImagesDefaultsMap {
		setDefaultIfEmpty(k, v)
	}
}

func (c *Cluster) setClusterNetworkDefaults() {
	setDefaultIfEmpty(&c.Network.Plugin, DefaultNetworkPlugin)

	if c.Network.Options == nil {
		// don't break if the user didn't define options
		c.Network.Options = make(map[string]string)
	}
	networkPluginConfigDefaultsMap := make(map[string]string)
	for k, v := range networkPluginConfigDefaultsMap {
		setDefaultIfEmptyMapValue(c.Network.Options, k, v)
	}

}
