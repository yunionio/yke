package cloudprovider

import (
	"yunion.io/yke/pkg/types"
)

type CloudProvider interface {
	Init(cloudProviderConfig types.CloudProvider) error
	GenerateCloudConfigFile() (string, error)
	GetName() string
}

func InitCloudProvider(cloudProviderConfig types.CloudProvider) (CloudProvider, error) {
	var p CloudProvider
	// TODO: impl
	return p, nil
}
