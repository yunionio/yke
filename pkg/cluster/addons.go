package cluster

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/addons"
	"yunion.io/x/yke/pkg/k8s"
)

const (
	UserAddonResourceName         = "yke-user-addon"
	IngressAddonResourceName      = "yke-ingress-controller"
	YunionCSIAddonResourceName    = "yke-yunion-csi-addon"
	UserAddonsIncludeResourceName = "yke-user-includes-addons"

	IngressAddonJobName            = "yke-ingress-controller-deploy-job"
	IngressAddonDeleteJobName      = "yke-ingress-controller-delete-job"
	MetricsServerAddonResourceName = "yke-metrics-addon"
	TillerAddonResourceName        = "yke-tiller-addon"
	HeapsterAddonResourceName      = "yke-heapster-addon"
	YunionCloudMonResourceName     = "yke-yunion-cloudmon-addon"
)

var DNSProviders = []string{"kubedns", "coredns"}

type ingressOptions struct {
	RBACConfig     string
	Options        map[string]string
	NodeSelector   map[string]string
	ExtraArgs      map[string]string
	AlpineImage    string
	IngressImage   string
	IngressBackend string
}

type CoreDNSOptions struct {
	RBACConfig             string
	CoreDNSImage           string
	CoreDNSAutoScalerImage string
	ClusterDomain          string
	ClusterDNSServer       string
	ReverseCIDRs           []string
	UpstreamNameservers    []string
	NodeSelector           map[string]string
}

type KubeDNSOptions struct {
	RBACConfig             string
	KubeDNSImage           string
	DNSMasqImage           string
	KubeDNSAutoScalerImage string
	KubeDNSSidecarImage    string
	ClusterDomain          string
	ClusterDNSServer       string
	ReverseCIDRs           []string
	UpstreamNameservers    []string
	NodeSelector           map[string]string
}

type MetricsServerOptions struct {
	RBACConfig         string
	Options            map[string]string
	MetricsServerImage string
	Version            string
}

type YunionCSIOptions struct {
	YunionAuthURL      string
	YunionAdminUser    string
	YunionAdminPasswd  string
	YunionAdminProject string
	YunionRegion       string
	CSIAttacher        string
	CSIProvisioner     string
	CSIRegistrar       string
	CSIImage           string
}

type TillerOptions struct {
	TillerImage string
}

type HeapsterOptions struct {
	HeapsterImage string
	InfluxdbUrl   string
}

type YunionCloudMonOptions struct {
	YunionAuthURL           string
	YunionDomain            string
	YunionAdminUser         string
	YunionAdminPasswd       string
	YunionAdminProject      string
	YunionRegion            string
	InfluxdbUrl             string
	YunionCloudMonitorImage string
}

type addonError struct {
	err        error
	isCritical bool
}

func (e *addonError) Error() string {
	return e.err.Error()
}

func getAddonResourceName(addon string) string {
	return fmt.Sprintf("yke-%s-addon", addon)
}

func (c *Cluster) deployK8sAddOns(ctx context.Context) error {
	if err := c.deployDNS(ctx); err != nil {
		if err, ok := err.(*addonError); ok && err.isCritical {
			return err
		}
		log.Warningf("Failed to deploy DNS addon execute job for provider %s: %v", c.DNS.Provider, err)
	}
	if c.Monitoring.Provider == DefaultMonitoringProvider {
		if err := c.deployMetricServer(ctx); err != nil {
			if err, ok := err.(*addonError); ok && err.isCritical {
				return err
			}
			log.Warningf("Failed to deploy addon execute job [%s]: %v", MetricsServerAddonResourceName, err)
		}
	}

	for key, df := range map[string]func(ctx context.Context) error{
		IngressAddonResourceName:   c.deployIngress,
		YunionCSIAddonResourceName: c.deployYunionCSI,
		TillerAddonResourceName:    c.deployTiller,
		HeapsterAddonResourceName:  c.deployHeapster,
		YunionCloudMonResourceName: c.deployYunionCloudMon,
	} {
		if err := df(ctx); err != nil {
			if err, ok := err.(*addonError); ok && err.isCritical {
				return err
			}
			log.Warningf("Failed to deploy addon execute job [%s]: %v", key, err)
		}
	}
	return nil
}

func (c *Cluster) deployUserAddOns(ctx context.Context) error {
	log.Infof("[addons] Setting up user addons")
	if c.Addons != "" {
		if err := c.doAddonDeployAsync(ctx, c.Addons, UserAddonResourceName, false); err != nil {
			return err
		}
	}
	if len(c.AddonsInclude) > 0 {
		if err := c.deployAddonsInclude(ctx); err != nil {
			return err
		}
	}
	if c.Addons == "" && len(c.AddonsInclude) == 0 {
		log.Infof("[addons] no user addons defined")
	} else {
		log.Infof("[addons] User addons deployed successfully")
	}
	return nil
}

func (c *Cluster) deployAddonsInclude(ctx context.Context) error {
	var manifests []byte
	log.Infof("[addons] Checking for included user addons")

	if len(c.AddonsInclude) == 0 {
		log.Infof("[addons] No included addon paths or urls..")
		return nil
	}
	for _, addon := range c.AddonsInclude {
		if strings.HasPrefix(addon, "http") {
			addonYAML, err := getAddonFromURL(addon)
			if err != nil {
				return err
			}
			log.Infof("[addons] Adding addon from url %s", addon)
			log.Debugf("URL Yaml: %s", addonYAML)

			if err := validateUserAddonYAML(addonYAML); err != nil {
				return err
			}
			manifests = append(manifests, addonYAML...)
		} else if isFilePath(addon) {
			addonYAML, err := ioutil.ReadFile(addon)
			if err != nil {
				return err
			}
			log.Infof("[addons] Adding addon from %s", addon)
			log.Debugf("FilePath Yaml: %s", string(addonYAML))

			// make sure we properly separated manifests
			addonYAMLStr := string(addonYAML)
			if !strings.HasPrefix(addonYAMLStr, "---") {
				addonYAML = []byte(fmt.Sprintf("%s\n%s", "---", addonYAMLStr))
			}
			if err := validateUserAddonYAML(addonYAML); err != nil {
				return err
			}
			manifests = append(manifests, addonYAML...)
		} else {
			log.Warningf("[addons] Unable to determine if %s is a file path or url, skipping", addon)
		}
	}
	log.Infof("[addons] Deploying %s", UserAddonsIncludeResourceName)
	log.Debugf("[addons] Compiled addons yaml: %s", string(manifests))

	return c.doAddonDeployAsync(ctx, string(manifests), UserAddonsIncludeResourceName, false)
}

func validateUserAddonYAML(addon []byte) error {
	yamlContents := make(map[string]interface{})

	return yaml.Unmarshal(addon, &yamlContents)
}

func isFilePath(addonPath string) bool {
	if _, err := os.Stat(addonPath); os.IsNotExist(err) {
		return false
	}
	return true
}

func getAddonFromURL(yamlURL string) ([]byte, error) {
	resp, err := http.Get(yamlURL)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	addonYaml, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return addonYaml, nil

}

func (c *Cluster) deployKubeDNS(ctx context.Context) error {
	if disableDns := ctx.Value("disable-kube-dns"); disableDns != nil && disableDns.(bool) {
		log.Infof("[KubeDNS] disable-kube-dns is specified, skipping deploy it")
		return nil
	}
	log.Infof("[addons] Setting up %s", c.DNS.Provider)
	kubeDNSConfig := KubeDNSOptions{
		KubeDNSImage:           c.SystemImages.KubeDNS,
		KubeDNSSidecarImage:    c.SystemImages.KubeDNSSidecar,
		KubeDNSAutoScalerImage: c.SystemImages.KubeDNSAutoscaler,
		DNSMasqImage:           c.SystemImages.DNSmasq,
		RBACConfig:             c.Authorization.Mode,
		ClusterDomain:          c.ClusterDomain,
		ClusterDNSServer:       c.ClusterDNSServer,
		UpstreamNameservers:    c.DNS.UpstreamNameservers,
		ReverseCIDRs:           c.DNS.ReverseCIDRs,
	}
	kubeDNSYaml, err := addons.GetKubeDNSManifest(kubeDNSConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, kubeDNSYaml, getAddonResourceName(c.DNS.Provider), false); err != nil {
		return err
	}
	log.Infof("[addons] KubeDNS deployed successfully..")
	return nil
}

func (c *Cluster) deployCoreDNS(ctx context.Context) error {
	if disableDns := ctx.Value("disable-kube-dns"); disableDns != nil && disableDns.(bool) {
		log.Infof("[CoreDNS] disable-kube-dns is specified, skipping deploy it")
		return nil
	}
	log.Infof("[addons] Setting up %s", c.DNS.Provider)
	CoreDNSConfig := CoreDNSOptions{
		CoreDNSImage: c.SystemImages.CoreDNS,
		//CoreDNSAutoScalerImage: c.SystemImages.CoreDNSAutoscaler,
		CoreDNSAutoScalerImage: c.SystemImages.KubeDNSAutoscaler,
		RBACConfig:             c.Authorization.Mode,
		ClusterDomain:          c.ClusterDomain,
		ClusterDNSServer:       c.ClusterDNSServer,
		UpstreamNameservers:    c.DNS.UpstreamNameservers,
		ReverseCIDRs:           c.DNS.ReverseCIDRs,
	}
	coreDNSYaml, err := addons.GetCoreDNSManifest(CoreDNSConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, coreDNSYaml, getAddonResourceName(c.DNS.Provider), false); err != nil {
		return err
	}
	log.Infof("[addons] CoreDNS deployed successfully..")
	return nil
}

func (c *Cluster) deployMetricServer(ctx context.Context) error {
	log.Infof("[addons] Setting up Metrics Server")
	s := strings.Split(c.SystemImages.MetricsServer, ":")
	versionTag := s[len(s)-1]
	MetricsServerConfig := MetricsServerOptions{
		MetricsServerImage: c.SystemImages.MetricsServer,
		RBACConfig:         c.Authorization.Mode,
		Options:            c.Monitoring.Options,
		Version:            getTagMajorVersion(versionTag),
	}
	metricsYaml, err := addons.GetMetricsServerManifest(MetricsServerConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, metricsYaml, MetricsServerAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] KubeDNS deployed sucessfully...")
	return nil
}

func (c *Cluster) deployWithKubectl(ctx context.Context, addonYaml string) error {
	buf := bytes.NewBufferString(addonYaml)
	cmd := exec.Command("kubectl", "--kubeconfig", c.LocalKubeConfigPath, "apply", "-f", "-")
	cmd.Stdin = buf
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *Cluster) doAddonDeployAsync(ctx context.Context, addonYaml, resourceName string, isCritical bool) error {
	return c.doAddonDeploy(ctx, addonYaml, resourceName, isCritical, true)
}

func (c *Cluster) doAddonDeploy(ctx context.Context, addonYaml, resourceName string, isCritical bool, async bool) error {
	if c.UseKubectlDeploy {
		if err := c.deployWithKubectl(ctx, addonYaml); err != nil {
			return &addonError{err, isCritical}
		}
	}

	addonUpdated, err := c.StoreAddonConfigMap(ctx, addonYaml, resourceName)
	if err != nil {
		return &addonError{fmt.Errorf("Failed to save addon ConfigMap: %v", err), isCritical}
	}

	log.Infof("[addons] Executing deploy job [%s] ...", resourceName)
	k8sClient, err := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
	if err != nil {
		return &addonError{err, isCritical}
	}
	node, err := k8s.GetNode(k8sClient, c.ControlPlaneHosts[0].HostnameOverride)
	if err != nil {
		return &addonError{fmt.Errorf("Failed to get Node [%s]: %v", c.ControlPlaneHosts[0].HostnameOverride, err), isCritical}
	}

	addonJob, err := addons.GetAddonsExcuteJob(resourceName, node.Name, c.Services.KubeAPI.Image)
	if err != nil {
		return &addonError{fmt.Errorf("Failed to deploy addon execute job: %v", err), isCritical}
	}

	if err = c.ApplySystemAddonExcuteJob(addonJob, addonUpdated, async); err != nil {
		return &addonError{fmt.Errorf("Failed to deploy addon execute job: %v", err), isCritical}
	}
	return nil
}

func (c *Cluster) doAddonDelete(ctx context.Context, resourceName string, isCritical bool) error {
	k8sClient, err := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
	if err != nil {
		return &addonError{err, isCritical}
	}
	node, err := k8s.GetNode(k8sClient, c.ControlPlaneHosts[0].HostnameOverride)
	if err != nil {
		return &addonError{fmt.Errorf("Failed to get Node [%s]: %v", c.ControlPlaneHosts[0].HostnameOverride, err), isCritical}
	}
	deleteJob, err := addons.GetAddonsDeleteJob(resourceName, node.Name, c.Services.KubeAPI.Image)
	if err != nil {
		return &addonError{fmt.Errorf("Failed to generate addon delete job: %v", err), isCritical}
	}
	if err := k8s.ApplyK8sSystemJob(deleteJob, c.LocalKubeConfigPath, c.K8sWrapTransport, c.AddonJobTimeout*2, false); err != nil {
		return &addonError{err, isCritical}
	}
	// At this point, the addon should be deleted. We need to clean up by deleting the deploy and delete jobs
	tmpJobYaml, err := addons.GetAddonsExcuteJob(resourceName, node.Name, c.Services.KubeAPI.Image)
	if err != nil {
		return err
	}
	if err := k8s.DeleteK8sSystemJob(tmpJobYaml, k8sClient, c.AddonJobTimeout); err != nil {
		return err
	}
	if err := k8s.DeleteK8sSystemJob(deleteJob, k8sClient, c.AddonJobTimeout); err != nil {
		return err
	}

	return nil
}

func (c *Cluster) StoreAddonConfigMap(ctx context.Context, addonYaml string, addonName string) (bool, error) {
	log.Infof("[addons] Saving addon ConfigMap to Kubernetes")
	updated := false
	kubeClient, err := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
	if err != nil {
		return updated, err
	}
	timeout := make(chan bool, 1)
	go func() {
		for {
			updated, err = k8s.UpdateConfigMap(kubeClient, []byte(addonYaml), addonName)
			if err != nil {
				time.Sleep(time.Second * 5)
				fmt.Println(err)
				continue
			}
			log.Infof("[addons] Successfully Saved addon to Kubernetes ConfigMap: %s", addonName)
			timeout <- true
			break
		}
	}()
	select {
	case <-timeout:
		return updated, nil
	case <-time.After(time.Second * UpdateStateTimeout):
		return updated, fmt.Errorf("[addons] Timeout waiting for kubernetes to be ready")
	}
}

func (c *Cluster) ApplySystemAddonExcuteJob(addonJob string, addonUpdated bool, async bool) error {
	if !async {
		if err := k8s.ApplyK8sSystemJob(addonJob, c.LocalKubeConfigPath, c.K8sWrapTransport, c.AddonJobTimeout, addonUpdated); err != nil {
			return err
		}
	} else {
		k8s.ApplyK8sSystemJobAsync(addonJob, c.LocalKubeConfigPath, c.K8sWrapTransport, c.AddonJobTimeout, addonUpdated)
	}
	return nil
}

func (c *Cluster) deployIngress(ctx context.Context) error {
	if disableIngress := ctx.Value("disable-ingress-controller"); disableIngress != nil && disableIngress.(bool) {
		log.Infof("[ingress] disable-ingress-controller is specified, skipping deploy")
		return nil
	}
	if c.Ingress.Provider == "none" {
		log.Infof("[ingress] ingress controller is not defined, skipping ingress controller")
		addonJobExists, err := addons.AddonJobExists(IngressAddonJobName, c.LocalKubeConfigPath, c.K8sWrapTransport)
		if err != nil {
			return nil
		}
		if addonJobExists {
			log.Infof("[ingress] removing installed ingress controller")
			if err := c.doAddonDelete(ctx, IngressAddonResourceName, false); err != nil {
				return err
			}

			log.Infof("[ingress] ingress controllerr removed successfully")
		} else {
			log.Infof("[ingress] ingress controller is disabled, skipping ingress controller")
		}
		return nil
	}
	log.Infof("[ingress] Setting up %s ingress controller", c.Ingress.Provider)
	ingressConfig := ingressOptions{
		RBACConfig:     c.Authorization.Mode,
		Options:        c.Ingress.Options,
		NodeSelector:   c.Ingress.NodeSelector,
		ExtraArgs:      c.Ingress.ExtraArgs,
		IngressImage:   c.SystemImages.Ingress,
		IngressBackend: c.SystemImages.IngressBackend,
	}
	// Currently only deploying nginx ingress controller
	ingressYaml, err := addons.GetNginxIngressManifest(ingressConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, ingressYaml, IngressAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[ingress] ingress controller %s is successfully deployed", c.Ingress.Provider)
	return nil
}

func (c *Cluster) deployYunionCSI(ctx context.Context) error {
	log.Infof("[csi] Setting up Yunion CSI plugin")
	// TODO: make yunion auth info options to global options
	csiConfig := YunionCSIOptions{
		YunionAuthURL:      c.YunionConfig.AuthURL,
		YunionAdminUser:    c.YunionConfig.AdminUser,
		YunionAdminPasswd:  c.YunionConfig.AdminPassword,
		YunionAdminProject: c.YunionConfig.AdminProject,
		YunionRegion:       c.YunionConfig.Region,
		CSIAttacher:        c.SystemImages.CSIAttacher,
		CSIProvisioner:     c.SystemImages.CSIProvisioner,
		CSIRegistrar:       c.SystemImages.CSIRegistrar,
		CSIImage:           c.SystemImages.YunionCSI,
	}
	csiYaml, err := addons.GetYunionCSIManifest(csiConfig)
	if err != nil {
		return err
	}
	jobExists, err := addons.AddonJobExists(YunionCSIAddonResourceName, c.LocalKubeConfigPath, c.K8sWrapTransport)
	if err != nil {
		return err
	}
	if jobExists {
		log.Infof("[csi] removing old csi provider %s", YunionCSIAddonResourceName)
		if err := c.doAddonDelete(ctx, YunionCSIAddonResourceName, false); err != nil {
			return err
		}
		log.Infof("[csi] %s removed successfully", YunionCSIAddonResourceName)
	}
	if err := c.doAddonDeployAsync(ctx, csiYaml, YunionCSIAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[csi] YunionCSI deployed successfully...")
	return nil
}

func (c *Cluster) deployTiller(ctx context.Context) error {
	log.Infof("[addons] setting up helm tiller plugin")
	config := TillerOptions{
		TillerImage: c.SystemImages.Tiller,
	}
	yaml, err := addons.GetTillerManifest(config)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, yaml, TillerAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] Tiller deployed successfully...")
	return nil
}

func (c *Cluster) deployHeapster(ctx context.Context) error {
	log.Infof("[addons] setting up heapster plugin")
	config := HeapsterOptions{
		HeapsterImage: c.SystemImages.Heapster,
		InfluxdbUrl:   c.YunionConfig.InfluxdbUrl,
	}
	yaml, err := addons.GetHeapsterManifest(config)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, yaml, HeapsterAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] Heapster deployed successfully...")
	return nil
}

func (c *Cluster) deployYunionCloudMon(ctx context.Context) error {
	log.Infof("[addons] setting up yunion cloud monitor plugin")
	config := YunionCloudMonOptions{
		YunionAuthURL:           c.YunionConfig.AuthURL,
		YunionDomain:            "Default",
		YunionAdminUser:         c.YunionConfig.AdminUser,
		YunionAdminPasswd:       c.YunionConfig.AdminPassword,
		YunionAdminProject:      c.YunionConfig.AdminProject,
		YunionRegion:            c.YunionConfig.Region,
		YunionCloudMonitorImage: c.SystemImages.YunionCloudMonitor,
		InfluxdbUrl:             c.YunionConfig.InfluxdbUrl,
	}
	yaml, err := addons.GetYunionCloudMoniotrManifest(config)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, yaml, YunionCloudMonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] Yunion cloud monitor deployed successfully...")
	return nil
}

func (c *Cluster) removeDNSProvider(ctx context.Context, dnsprovider string) error {
	AddonJobExists, err := addons.AddonJobExists(getAddonResourceName(dnsprovider)+"-deploy-job", c.LocalKubeConfigPath, c.K8sWrapTransport)
	if err != nil {
		return err
	}
	if AddonJobExists {
		log.Infof("[dns] removing DNS provider %s", dnsprovider)
		if err := c.doAddonDelete(ctx, getAddonResourceName(dnsprovider), false); err != nil {
			return err
		}
		log.Infof("[dns] DNS provider %s removed successfully", dnsprovider)
		return nil
	}
	return nil
}

func (c *Cluster) deployDNS(ctx context.Context) error {
	switch DNSProvider := c.DNS.Provider; DNSProvider {
	case "kubedns":
		for _, dnsprovider := range DNSProviders {
			if strings.EqualFold(dnsprovider, DefaultDNSProvider) {
				continue
			}
			if err := c.removeDNSProvider(ctx, dnsprovider); err != nil {
				return nil
			}
		}
		if err := c.deployKubeDNS(ctx); err != nil {
			if err, ok := err.(*addonError); ok && err.isCritical {
				return err
			}
			log.Warningf("Failed to deploy addon execute job [%s]: %v", getAddonResourceName(c.DNS.Provider), err)
		}
		log.Infof("[dns] DNS provider %s deployed successfully", c.DNS.Provider)
		return nil
	case "coredns":
		for _, dnsprovider := range DNSProviders {
			if strings.EqualFold(dnsprovider, "coredns") {
				continue
			}
			if err := c.removeDNSProvider(ctx, dnsprovider); err != nil {
				return nil
			}
		}
		if err := c.deployCoreDNS(ctx); err != nil {
			if err, ok := err.(*addonError); ok && err.isCritical {
				return err
			}
			log.Warningf("Failed to deploy addon execute job [%s]: %v", getAddonResourceName(c.DNS.Provider), err)
		}
		log.Infof("[dns] DNS provider %s deployed successfully", c.DNS.Provider)
		return nil
	case "none":
		// Check all DNS providers and remove if present
		for _, dnsprovider := range DNSProviders {
			if err := c.removeDNSProvider(ctx, dnsprovider); err != nil {
				return nil
			}
		}
		return nil
	default:
		log.Warningf("[dns] No valid DNS provider configured: %s", c.DNS.Provider)
		return nil
	}
}
