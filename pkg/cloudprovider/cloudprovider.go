package cloudprovider

import (
	"yunion.io/x/yke/pkg/cloudprovider/yunion"
	"yunion.io/x/yke/pkg/types"
)

type CloudProvider interface {
	Init(cloudProviderConfig types.CloudProvider) error
	GenerateCloudConfigFile() (string, error)
	GetName() string
}

func InitCloudProvider(cloudProviderConfig types.CloudProvider) (CloudProvider, error) {
	var p CloudProvider
	p = yunion.GetInstance()
	if err := p.Init(cloudProviderConfig); err != nil {
		return nil, err
	}
	return p, nil
}
