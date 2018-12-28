package yunion

import (
	"encoding/json"
	"fmt"

	"yunion.io/x/yke/pkg/types"
)

const (
	YunionCloudProviderName = "yunion"
	ExtraCloudProviderName  = "extra"
)

type CloudProvider struct {
	Name   string
	Config *types.YunionCloudProvider
}

func GetInstance() *CloudProvider {
	return &CloudProvider{}
}

func (p *CloudProvider) Init(config types.CloudProvider) error {
	if config.YunionCloudProvider == nil {
		return fmt.Errorf("Cloud provider config is empty")
	}
	//p.Name = YunionCloudProviderName
	p.Name = ExtraCloudProviderName
	p.Config = config.YunionCloudProvider
	return nil
}

func (p *CloudProvider) GenerateCloudConfigFile() (string, error) {
	conf, err := json.MarshalIndent(p.Config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(conf), nil
}

func (p *CloudProvider) GetName() string {
	return p.Name
}
