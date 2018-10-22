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
	KubeDNSAddonResourceName      = "yke-kubedns-addon"
	UserAddonResourceName         = "yke-user-addon"
	IngressAddonResourceName      = "yke-ingress-controller"
	YunionCSIAddonResourceName    = "yke-yunion-csi-addon"
	YunionLXCFSAddonResourceName  = "yke-yunion-lxcfs-addon"
	UserAddonsIncludeResourceName = "yke-user-includes-addons"

	IngressAddonJobName            = "yke-ingress-controller-deploy-job"
	IngressAddonDeleteJobName      = "yke-ingress-controller-delete-job"
	MetricsServerAddonResourceName = "yke-metrics-addon"
)

type ingressOptions struct {
	RBACConfig     string
	Options        map[string]string
	NodeSelector   map[string]string
	ExtraArgs      map[string]string
	AlpineImage    string
	IngressImage   string
	IngressBackend string
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

type YunionLXCFSOptions struct {
	LXCFSInitImage string
}

type addonError struct {
	err        error
	isCritical bool
}

func (e *addonError) Error() string {
	return e.err.Error()
}

func (c *Cluster) deployK8sAddOns(ctx context.Context) error {
	if err := c.deployKubeDNS(ctx); err != nil {
		if err, ok := err.(*addonError); ok && err.isCritical {
			return err
		}
		log.Warningf("Failed to deploy addon execute job [%s]: %v", KubeDNSAddonResourceName, err)
	}
	if c.Monitoring.Provider == DefaultMonitoringProvider {
		if err := c.deployMetricServer(ctx); err != nil {
			if err, ok := err.(*addonError); ok && err.isCritical {
				return err
			}
			log.Warningf("Failed to deploy addon execute job [%s]: %v", MetricsServerAddonResourceName, err)
		}
	}
	if err := c.deployIngress(ctx); err != nil {
		if err, ok := err.(*addonError); ok && err.isCritical {
			return err
		}
		log.Warningf("Failed to deploy addon execute job [%s]: %v", IngressAddonResourceName, err)
	}
	if err := c.deployYunionCSI(ctx); err != nil {
		if err, ok := err.(*addonError); ok && err.isCritical {
			return err
		}
		log.Warningf("Failed to deploy addon execute job [%s]: %v", YunionCSIAddonResourceName, err)
	}
	if err := c.deployYunionLXCFS(ctx); err != nil {
		if err, ok := err.(*addonError); ok && err.isCritical {
			return err
		}
		log.Warningf("Failed to deploy addon execute job [%s]: %v", YunionLXCFSAddonResourceName, err)
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
	log.Infof("[addons] Setting up KubeDNS")
	kubeDNSConfig := map[string]string{
		addons.KubeDNSServer:          c.ClusterDNSServer,
		addons.KubeDNSClusterDomain:   c.ClusterDomain,
		addons.KubeDNSImage:           c.SystemImages.KubeDNS,
		addons.DNSMasqImage:           c.SystemImages.DNSmasq,
		addons.KubeDNSSidecarImage:    c.SystemImages.KubeDNSSidecar,
		addons.KubeDNSAutoScalerImage: c.SystemImages.KubeDNSAutoscaler,
		addons.RBAC:                   c.Authorization.Mode,
	}
	kubeDNSYaml, err := addons.GetKubeDNSManifest(kubeDNSConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, kubeDNSYaml, KubeDNSAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] KubeDNS deployed successfully..")
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
	log.Infof("[addons] Setting up Yunion CSI plugin")
	// TODO: make yunion auth info options to global options
	csiConfig := YunionCSIOptions{
		YunionAuthURL:      c.Network.Options[YunionAuthURL],
		YunionAdminUser:    c.Network.Options[YunionAdminUser],
		YunionAdminPasswd:  c.Network.Options[YunionAdminPasswd],
		YunionAdminProject: c.Network.Options[YunionAdminProject],
		YunionRegion:       c.Network.Options[YunionRegion],
		CSIAttacher:        c.SystemImages.CSIAttacher,
		CSIProvisioner:     c.SystemImages.CSIProvisioner,
		CSIRegistrar:       c.SystemImages.CSIRegistrar,
		CSIImage:           c.SystemImages.YunionCSI,
	}
	csiYaml, err := addons.GetYunionCSIManifest(csiConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, csiYaml, YunionCSIAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] YunionCSI deployed successfully...")
	return nil
}

func (c *Cluster) deployYunionLXCFS(ctx context.Context) error {
	if enableLxcfs := ctx.Value("enable-lxcfs"); enableLxcfs == nil || !enableLxcfs.(bool) {
		return nil
	}
	log.Infof("[addons] Setting up Yunion LXCFS plugin")
	lxcfsConfig := YunionLXCFSOptions{
		LXCFSInitImage: c.SystemImages.LXCFSInitializer,
	}
	yaml, err := addons.GetYunionLXCFSManifest(lxcfsConfig)
	if err != nil {
		return err
	}
	if err := c.doAddonDeployAsync(ctx, yaml, YunionLXCFSAddonResourceName, false); err != nil {
		return err
	}
	log.Infof("[addons] YunionLXCFS deployed successfully...")
	return nil
}
