package cluster

const (
	KubeAPIPort    = "6443"
	EtcdPort1      = "2379"
	EtcdPort2      = "2380"
	ScedulerPort   = "10251"
	ControllerPort = "10252"
	KubeletPort    = "10250"
	KubeProxyPort  = "10256"

	ProtocolTCP = "TCP"
	ProtocolUDP = "UDP"

	// yunion specified
	YunionNetworkPlugin = "yunion"
	YunionCNIImage      = "yunion_cni_image"
	YunionBridge        = "yunion_bridge"
	YunionAuthURL       = "yunion_auth_url"
	YunionAdminUser     = "yunion_admin_user"
	YunionAdminPasswd   = "yunion_admin_passwd"
	YunionAdminProject  = "yunion_admin_project"
	YunionRegion        = "yunion_region"
)
