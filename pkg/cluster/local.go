package cluster

import (
	"yunion.io/yke/pkg/services"
	"yunion.io/yke/pkg/types"
)

func GetLocalConfig() *types.KubernetesEngineConfig {
	localNode := GetLocalNodeConfig()
	imageDefaults := types.K8sVersionToSystemImages[DefaultK8sVersion]

	keServices := types.ConfigServices{
		Kubelet: types.KubeletService{
			BaseService: types.BaseService{
				Image:     imageDefaults.Kubernetes,
				ExtraArgs: map[string]string{"fail-swap-on": "false"},
			},
		},
	}
	return &types.KubernetesEngineConfig{
		Nodes:    []types.ConfigNode{*localNode},
		Services: keServices,
	}

}

func GetLocalNodeConfig() *types.ConfigNode {
	localNode := &types.ConfigNode{
		Address:          LocalNodeAddress,
		HostnameOverride: LocalNodeHostname,
		User:             LocalNodeUser,
		Role:             []string{services.ControlRole, services.WorkerRole, services.ETCDRole},
	}
	return localNode
}
