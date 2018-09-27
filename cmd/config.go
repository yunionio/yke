package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/urfave/cli"
	"gopkg.in/yaml.v2"

	"yunion.io/x/log"
	"yunion.io/x/pkg/util/sets"

	"yunion.io/x/yke/pkg/cluster"
	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/services"
	"yunion.io/x/yke/pkg/types"
)

const (
	comments = `# If you intened to deploy Kubernetes in an air-gapped environment,
# please consult the documentation on how to configure custom YKE images.`
)

var (
	roleSets sets.String = sets.NewString(services.ControlRole, services.ETCDRole, services.WorkerRole)
)

func ConfigCommand() cli.Command {
	return cli.Command{
		Name:   "config",
		Usage:  "Setup cluster configuration",
		Action: clusterConfig,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "name,n",
				Usage: "Name of the configuration file",
				Value: pki.ClusterConfig,
			},
			cli.BoolFlag{
				Name:  "empty,e",
				Usage: "Generate Empty configuration file",
			},
			cli.BoolFlag{
				Name:  "print,p",
				Usage: "Print configuration",
			},
			cli.BoolFlag{
				Name:  "system-images",
				Usage: "Generate the default system images",
			},
			cli.BoolFlag{
				Name:  "all",
				Usage: "Generate the default system images for all versions",
			},
			cli.StringFlag{
				Name:  "version",
				Usage: "Generate the default system images for specific k8s versions",
			},
			cli.StringFlag{
				Name:  "topo,t",
				Usage: "Cluster topo like: controlplane:10.168.26.183/etcd:10.168.26.183/worker:10.168.26.183,10.168.26.184",
			},
			cli.StringFlag{
				Name:  "user,u",
				Usage: "SSH user",
				Value: "yunion",
			},
			cli.StringFlag{
				Name:  "key,k",
				Usage: "SSH private key path",
				Value: "/home/yunion/.ssh/yke_id_rsa",
			},
			cli.StringFlag{
				Name:  "yunion-webhook-url",
				Usage: "Yunion keystone webhook auth url",
				Value: "http://127.0.0.1:8440/webhook",
			},
			cli.StringFlag{
				Name:   "os-username",
				Usage:  "Yunion keystone auth username",
				EnvVar: "OS_USERNAME",
			},
			cli.StringFlag{
				Name:   "os-password",
				Usage:  "Yunion keystone auth password",
				EnvVar: "OS_PASSWORD",
			},
			cli.StringFlag{
				Name:   "os-project-name",
				Usage:  "Yunion keystone project name",
				Value:  "system",
				EnvVar: "OS_PROJECT_NAME",
			},
			cli.StringFlag{
				Name:   "os-domain-name",
				Usage:  "Yunion keystone domain name",
				Value:  "Default",
				EnvVar: "OS_DOMAIN_NAME",
			},
			cli.StringFlag{
				Name:   "os-auth-url",
				Usage:  "Yunion keystone auth url",
				EnvVar: "OS_AUTH_URL",
			},
			cli.StringFlag{
				Name:   "os-region-name",
				Usage:  "Yunion region name",
				EnvVar: "OS_REGION_NAME",
			},
			cli.StringFlag{
				Name:  "yunion-cni-bridge",
				Usage: "Yunion cni plugin ovs bridge",
				Value: "br0",
			},
		},
	}
}

func getConfig(reader *bufio.Reader, text, def string) (string, error) {
	for {
		if def == "" {
			fmt.Printf("[+] %s [%s]: ", text, "none")
		} else {
			fmt.Printf("[+] %s [%s]: ", text, def)
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)

		if input != "" {
			return input, nil
		}
		return def, nil
	}
}

func writeConfig(cluster *types.KubernetesEngineConfig, configFile string, print bool) error {
	yamlConfig, err := yaml.Marshal(*cluster)
	if err != nil {
		return err
	}
	log.Debugf("Deploying cluster configuration file: %s", configFile)

	configString := fmt.Sprintf("%s\n%s", comments, string(yamlConfig))
	if print {
		fmt.Printf("Configuration File: \n%s", configString)
		return nil
	}
	return ioutil.WriteFile(configFile, []byte(configString), 0640)
}

func parseNodesTopo(topo, privateKeyPath, privateKey, sshUser string) ([]types.ConfigNode, error) {
	nodes := make([]*types.ConfigNode, 0)
	rolesIPs := strings.Split(topo, "/")

	nodeByIP := func(nodes []*types.ConfigNode, ip string) *types.ConfigNode {
		for _, n := range nodes {
			if n.InternalAddress == ip {
				return n
			}
		}
		return nil
	}

	nodeAddRole := func(node *types.ConfigNode, role string) *types.ConfigNode {
		rs := sets.NewString(node.Role...)
		if rs.Has(role) {
			return node
		}
		node.Role = append(node.Role, role)
		return node
	}

	for _, roleIPs := range rolesIPs {
		roleIPsL := strings.Split(roleIPs, ":")
		if len(roleIPsL) != 2 {
			return nil, fmt.Errorf("Invalid topo string: %q", topo)
		}
		role, ips := roleIPsL[0], roleIPsL[1]
		if len(role) == 0 || !roleSets.Has(role) {
			return nil, fmt.Errorf("Invalid role: %q", role)
		}
		ipsL := strings.Split(ips, ",")
		if len(ipsL) == 0 {
			return nil, fmt.Errorf("Invalid host IP: %q", ips)
		}
		for _, ip := range ipsL {
			n := nodeByIP(nodes, ip)
			if n == nil {
				n = &types.ConfigNode{}
				n = setNodeDefaultsConfig(n, ip, privateKeyPath, privateKey, sshUser, role)
				nodes = append(nodes, n)
			}
			n = nodeAddRole(n, role)
		}
	}
	iNodes := make([]types.ConfigNode, 0)
	for _, n := range nodes {
		if len(n.Address) == 0 {
			continue
		}
		iNodes = append(iNodes, *n)
	}
	return iNodes, nil
}

func setNodeDefaultsConfig(node *types.ConfigNode, ip, privateKeyPath, privateKey, sshUser, role string) *types.ConfigNode {
	node.Address = ip
	node.Port = cluster.DefaultSSHPort
	node.SSHKeyPath = privateKeyPath
	node.SSHKey = privateKey
	node.User = sshUser
	node.Role = []string{role}
	node.InternalAddress = ip
	node.DockerSocket = cluster.DefaultDockerSockPath
	return node
}

type YunionAuthOptions struct {
	OsAuthURL     string
	OsUsername    string
	OsPassword    string
	OsProjectName string
	OsRegionName  string
}

type YunionWebhookAuthConfig struct {
	*YunionAuthOptions
	URL string
}

func parseYunionWebhookAuthConfig(ctx *cli.Context, auth *YunionAuthOptions) *YunionWebhookAuthConfig {
	url := ctx.String("yunion-webhook-url")
	if len(url) == 0 {
		return nil
	}
	return &YunionWebhookAuthConfig{
		YunionAuthOptions: auth,
		URL:               url,
	}
}

func directlyTopoConfig(ctx *cli.Context, configFile string, print bool) error {
	clusterTopo := ctx.String("topo")
	sshUser := ctx.String("user")
	privateKeyPath := ctx.String("key")
	authUrl := ctx.String("os-auth-url")
	username := ctx.String("os-username")
	password := ctx.String("os-password")
	project := ctx.String("os-project-name")
	//domain := ctx.String("os-domain-name")
	region := ctx.String("os-region-name")
	webhookUrl := ctx.String("yunion-webhook-url")
	if len(clusterTopo) == 0 {
		return fmt.Errorf("Cluster topo empty")
	}
	if len(sshUser) == 0 {
		return fmt.Errorf("SshUser not specified")
	}
	if len(privateKeyPath) == 0 {
		return fmt.Errorf("SSH private key path not provided")
	}
	pKey, err := hosts.PrivateKeyPath(privateKeyPath)
	if err != nil {
		return fmt.Errorf("Get private key content: %v", err)
	}
	nodes, err := parseNodesTopo(clusterTopo, privateKeyPath, pKey, sshUser)
	if err != nil {
		return fmt.Errorf("Parse cluster topo %q: %v", clusterTopo, err)
	}
	if len(authUrl) == 0 {
		return fmt.Errorf("os-auth-url must provided")
	}
	if len(username) == 0 {
		return fmt.Errorf("os-username must specified")
	}
	if len(password) == 0 {
		return fmt.Errorf("os-password must provided")
	}
	if len(project) == 0 {
		return fmt.Errorf("os-project-name must provided")
	}
	if len(region) == 0 {
		return fmt.Errorf("os-region-name must specified")
	}
	if len(webhookUrl) == 0 {
		return fmt.Errorf("yunion-webhook-url must specified")
	}
	c := types.KubernetesEngineConfig{}
	c.Nodes = nodes
	c.SSHKeyPath = privateKeyPath
	yunionAuthOpt := &YunionAuthOptions{
		OsAuthURL:     authUrl,
		OsUsername:    username,
		OsPassword:    password,
		OsProjectName: project,
		OsRegionName:  region,
	}
	yunionWebhookConfig := parseYunionWebhookAuthConfig(ctx, yunionAuthOpt)
	setTopoConfigDefaults(ctx, &c, yunionWebhookConfig)
	return writeConfig(&c, configFile, print)
}

func setTopoConfigDefaults(ctx *cli.Context, c *types.KubernetesEngineConfig, yunionWebhookAuth *YunionWebhookAuthConfig) {
	c.Network = types.NetworkConfig{Plugin: cluster.DefaultNetworkPlugin}
	c.Authorization = types.AuthzConfig{Mode: cluster.DefaultAuthorizationMode}

	servicesConfig := types.ConfigServices{}
	imageDefaults := types.K8sVersionToSystemImages[cluster.DefaultK8sVersion]
	servicesConfig.Etcd = types.ETCDService{
		BaseService: types.BaseService{Image: imageDefaults.Etcd},
	}
	servicesConfig.KubeAPI = types.KubeAPIService{
		BaseService: types.BaseService{
			Image: imageDefaults.Kubernetes,
		},
	}
	servicesConfig.KubeController = types.KubeControllerService{
		BaseService: types.BaseService{
			Image: imageDefaults.Kubernetes,
		},
	}
	servicesConfig.Scheduler = types.SchedulerService{
		BaseService: types.BaseService{
			Image: imageDefaults.Kubernetes,
		},
	}
	servicesConfig.Kubelet = types.KubeletService{
		BaseService: types.BaseService{
			Image: imageDefaults.Kubernetes,
		},
	}
	servicesConfig.Kubeproxy = types.KubeproxyService{
		BaseService: types.BaseService{
			Image: imageDefaults.Kubernetes,
		},
	}
	c.WebhookAuth.URL = yunionWebhookAuth.URL
	servicesConfig.KubeAPI.ExtraArgs = map[string]string{
		"authentication-token-webhook-config-file": "/etc/kubernetes/webhook.kubeconfig",
	}
	servicesConfig.Kubelet.ClusterDomain = cluster.DefaultClusterDomain
	servicesConfig.KubeAPI.ServiceClusterIPRange = cluster.DefaultServiceClusterIPRange
	servicesConfig.KubeController.ServiceClusterIPRange = cluster.DefaultServiceClusterIPRange
	servicesConfig.KubeAPI.PodSecurityPolicy = false
	servicesConfig.KubeController.ClusterCIDR = cluster.DefaultClusterCIDR
	servicesConfig.Kubelet.ClusterDNSServer = cluster.DefaultClusterDNSService
	servicesConfig.Kubelet.InfraContainerImage = imageDefaults.PodInfraContainer

	c.Services = servicesConfig

	// Yunion CNI options
	c.Network.Options = map[string]string{
		cluster.YunionBridge:       ctx.String("yunion-cni-bridge"),
		cluster.YunionAuthURL:      yunionWebhookAuth.OsAuthURL,
		cluster.YunionAdminUser:    yunionWebhookAuth.OsUsername,
		cluster.YunionAdminPasswd:  yunionWebhookAuth.OsPassword,
		cluster.YunionAdminProject: yunionWebhookAuth.OsProjectName,
		cluster.YunionRegion:       yunionWebhookAuth.OsRegionName,
	}
}

func clusterConfig(ctx *cli.Context) error {
	if ctx.Bool("system-images") {
		return generateSystemImagesList(ctx.String("version"), ctx.Bool("all"))
	}
	configFile := ctx.String("name")
	print := ctx.Bool("print")
	cluster := types.KubernetesEngineConfig{}

	// Get cluster config from user
	reader := bufio.NewReader(os.Stdin)

	// Generate empty configuration file
	if ctx.Bool("empty") {
		cluster.Nodes = make([]types.ConfigNode, 1)
		return writeConfig(&cluster, configFile, print)
	}

	if len(ctx.String("topo")) != 0 {
		return directlyTopoConfig(ctx, configFile, print)
	}

	sshKeyPath, err := getConfig(reader, "Cluster Level SSH Private Key Path", "~/.ssh/id_rsa")
	if err != nil {
		return err
	}
	cluster.SSHKeyPath = sshKeyPath

	// Get number of hosts
	numberOfHostsString, err := getConfig(reader, "Number of Hosts", "1")
	if err != nil {
		return err
	}
	numberOfHostsInt, err := strconv.Atoi(numberOfHostsString)
	if err != nil {
		return err
	}

	// Get Hosts config
	cluster.Nodes = make([]types.ConfigNode, 0)
	for i := 0; i < numberOfHostsInt; i++ {
		hostCfg, err := getHostConfig(reader, i, cluster.SSHKeyPath)
		if err != nil {
			return err
		}
		cluster.Nodes = append(cluster.Nodes, *hostCfg)
	}

	// Get Network config
	networkConfig, err := getNetworkConfig(reader)
	if err != nil {
		return err
	}
	cluster.Network = *networkConfig

	// Get Authentication Config
	authnConfig, err := getAuthnConfig(reader)
	if err != nil {
		return err
	}
	cluster.Authentication = *authnConfig

	// Get Authorization config
	authzConfig, err := getAuthzConfig(reader)
	if err != nil {
		return err
	}
	cluster.Authorization = *authzConfig

	// Get k8s/system images
	systemImages, err := getSystemImagesConfig(reader)
	if err != nil {
		return err
	}
	cluster.SystemImages = *systemImages

	// Get Services Config
	serviceConfig, err := getServiceConfig(reader)
	if err != nil {
		return err
	}
	cluster.Services = *serviceConfig

	// Get addon manifests
	addonsInclude, err := getAddonManifests(reader)
	if err != nil {
		return err
	}

	if len(addonsInclude) > 0 {
		cluster.AddonsInclude = append(cluster.AddonsInclude, addonsInclude...)
	}

	return writeConfig(&cluster, configFile, print)
}

func getHostConfig(reader *bufio.Reader, index int, clusterSSHKeyPath string) (*types.ConfigNode, error) {
	host := types.ConfigNode{}

	address, err := getConfig(reader, fmt.Sprintf("SSH Address of host (%d)", index+1), "")
	if err != nil {
		return nil, err
	}
	host.Address = address

	port, err := getConfig(reader, fmt.Sprintf("SSH Port of host (%d)", index+1), cluster.DefaultSSHPort)
	if err != nil {
		return nil, err
	}
	host.Port = port

	sshKeyPath, err := getConfig(reader, fmt.Sprintf("SSH Private Key Path of host (%s)", address), "")
	if err != nil {
		return nil, err
	}
	if len(sshKeyPath) == 0 {
		fmt.Printf("[-] You have entered empty SSH key path, trying fetch from SSH key parameter\n")
		sshKey, err := getConfig(reader, fmt.Sprintf("SSH Private Key of host (%s)", address), "")
		if err != nil {
			return nil, err
		}
		if len(sshKey) == 0 {
			fmt.Printf("[-] You have entered empty SSH key, defaulting to cluster level SSH key: %s\n", clusterSSHKeyPath)
			host.SSHKeyPath = clusterSSHKeyPath
		} else {
			host.SSHKey = sshKey
		}
	} else {
		host.SSHKeyPath = sshKeyPath
	}

	sshUser, err := getConfig(reader, fmt.Sprintf("SSH User of host (%s)", address), "ubuntu")
	if err != nil {
		return nil, err
	}
	host.User = sshUser

	isControlHost, err := getConfig(reader, fmt.Sprintf("Is host (%s) a Control Plane host (y/n)?", address), "y")
	if err != nil {
		return nil, err
	}
	if isControlHost == "y" || isControlHost == "Y" {
		host.Role = append(host.Role, services.ControlRole)
	}

	isWorkerHost, err := getConfig(reader, fmt.Sprintf("Is host (%s) a Worker host (y/n)?", address), "n")
	if err != nil {
		return nil, err
	}
	if isWorkerHost == "y" || isWorkerHost == "Y" {
		host.Role = append(host.Role, services.WorkerRole)
	}

	isEtcdHost, err := getConfig(reader, fmt.Sprintf("Is host (%s) an Etcd host (y/n)?", address), "n")
	if err != nil {
		return nil, err
	}
	if isEtcdHost == "y" || isEtcdHost == "Y" {
		host.Role = append(host.Role, services.ETCDRole)
	}

	hostnameOverride, err := getConfig(reader, fmt.Sprintf("Override Hostname of host (%s)", address), "")
	if err != nil {
		return nil, err
	}
	host.HostnameOverride = hostnameOverride

	internalAddress, err := getConfig(reader, fmt.Sprintf("Internal IP of host (%s)", address), "")
	if err != nil {
		return nil, err
	}
	host.InternalAddress = internalAddress

	dockerSocketPath, err := getConfig(reader, fmt.Sprintf("Docker socket path on host (%s)", address), cluster.DefaultDockerSockPath)
	if err != nil {
		return nil, err
	}
	host.DockerSocket = dockerSocketPath
	return &host, nil
}

func getSystemImagesConfig(reader *bufio.Reader) (*types.SystemImages, error) {
	imageDefaults := types.K8sVersionToSystemImages[cluster.DefaultK8sVersion]

	kubeImage, err := getConfig(reader, "Kubernetes Docker image", imageDefaults.Kubernetes)
	if err != nil {
		return nil, err
	}

	systemImages, ok := types.K8sVersionToSystemImages[kubeImage]
	if ok {
		return &systemImages, nil
	}
	imageDefaults.Kubernetes = kubeImage
	return &imageDefaults, nil
}

func getServiceConfig(reader *bufio.Reader) (*types.ConfigServices, error) {
	servicesConfig := types.ConfigServices{}
	servicesConfig.Etcd = types.ETCDService{}
	servicesConfig.KubeAPI = types.KubeAPIService{}
	servicesConfig.KubeController = types.KubeControllerService{}
	servicesConfig.Scheduler = types.SchedulerService{}
	servicesConfig.Kubelet = types.KubeletService{}
	servicesConfig.Kubeproxy = types.KubeproxyService{}

	clusterDomain, err := getConfig(reader, "Cluster domain", cluster.DefaultClusterDomain)
	if err != nil {
		return nil, err
	}
	servicesConfig.Kubelet.ClusterDomain = clusterDomain

	serviceClusterIPRange, err := getConfig(reader, "Service Cluster IP Range", cluster.DefaultServiceClusterIPRange)
	if err != nil {
		return nil, err
	}
	servicesConfig.KubeAPI.ServiceClusterIPRange = serviceClusterIPRange
	servicesConfig.KubeController.ServiceClusterIPRange = serviceClusterIPRange

	podSecurityPolicy, err := getConfig(reader, "Enable PodSecurityPolicy", "n")
	if err != nil {
		return nil, err
	}
	if podSecurityPolicy == "y" || podSecurityPolicy == "Y" {
		servicesConfig.KubeAPI.PodSecurityPolicy = true
	} else {
		servicesConfig.KubeAPI.PodSecurityPolicy = false
	}

	clusterNetworkCidr, err := getConfig(reader, "Cluster Network CIDR", cluster.DefaultClusterCIDR)
	if err != nil {
		return nil, err
	}
	servicesConfig.KubeController.ClusterCIDR = clusterNetworkCidr

	clusterDNSServiceIP, err := getConfig(reader, "Cluster DNS Service IP", cluster.DefaultClusterDNSService)
	if err != nil {
		return nil, err
	}
	servicesConfig.Kubelet.ClusterDNSServer = clusterDNSServiceIP

	return &servicesConfig, nil
}

func getAuthnConfig(reader *bufio.Reader) (*types.AuthnConfig, error) {
	authnConfig := types.AuthnConfig{}

	authnType, err := getConfig(reader, "Authentication Strategy", cluster.DefaultAuthStrategy)
	if err != nil {
		return nil, err
	}
	authnConfig.Strategy = authnType
	return &authnConfig, nil
}

func getAuthzConfig(reader *bufio.Reader) (*types.AuthzConfig, error) {
	authzConfig := types.AuthzConfig{}
	authzMode, err := getConfig(reader, "Authorization Mode (rbac, none)", cluster.DefaultAuthorizationMode)
	if err != nil {
		return nil, err
	}
	authzConfig.Mode = authzMode
	return &authzConfig, nil
}

func getNetworkConfig(reader *bufio.Reader) (*types.NetworkConfig, error) {
	networkConfig := types.NetworkConfig{}

	networkPlugin, err := getConfig(reader, "Network Plugin Type (yunion)", cluster.DefaultNetworkPlugin)
	if err != nil {
		return nil, err
	}
	networkConfig.Plugin = networkPlugin
	return &networkConfig, nil
}

func getAddonManifests(reader *bufio.Reader) ([]string, error) {
	var addonSlice []string
	var resume = true

	includeAddons, err := getConfig(reader, "Add addon manifest URLs or YAML files", "no")
	if err != nil {
		return nil, err
	}

	if strings.ContainsAny(includeAddons, "Yes YES Y yes y") {
		for resume {
			addonPath, err := getConfig(reader, "Enter the path or URL for the manifest", "")
			if err != nil {
				return nil, err
			}

			addonSlice = append(addonSlice, addonPath)

			cont, err := getConfig(reader, "Add another addon", "no")
			if err != nil {
				return nil, err
			}

			if strings.ContainsAny(cont, "Yes y Y yes YES") {
				resume = true
			} else {
				resume = false
			}
		}
	}

	return addonSlice, nil
}

func generateSystemImagesList(version string, all bool) error {
	allVersions := []string{}
	for version := range types.AllK8sVersions {
		allVersions = append(allVersions, version)
	}
	if all {
		for version, ykeSystemImages := range types.AllK8sVersions {
			log.Infof("Generating images list for version [%s]:", version)
			uniqueImages := getUniqueSystemImageList(ykeSystemImages)
			for _, image := range uniqueImages {
				if image == "" {
					continue
				}
				fmt.Printf("%s\n", image)
			}
		}
		return nil
	}
	if len(version) == 0 {
		version = types.DefaultK8s
	}
	ykeSystemImages := types.AllK8sVersions[version]
	if ykeSystemImages == (types.SystemImages{}) {
		return fmt.Errorf("k8s version is not supported, supported version are: %v", allVersions)
	}
	log.Infof("Generating images list for version [%s]: ", version)
	uniqueImages := getUniqueSystemImageList(ykeSystemImages)
	for _, image := range uniqueImages {
		if image == "" {
			continue
		}
		fmt.Printf("%s\n", image)
	}
	return nil
}

func getUniqueSystemImageList(ykeSystemImages types.SystemImages) []string {
	imagesReflect := reflect.ValueOf(ykeSystemImages)
	images := make([]string, imagesReflect.NumField())
	for i := 0; i < imagesReflect.NumField(); i++ {
		images[i] = imagesReflect.Field(i).Interface().(string)
	}
	return getUniqueSlice(images)
}

func getUniqueSlice(slice []string) []string {
	encountered := map[string]bool{}
	unique := []string{}

	for i := range slice {
		if encountered[slice[i]] {
			continue
		} else {
			encountered[slice[i]] = true
			unique = append(unique, slice[i])
		}
	}
	return unique
}
