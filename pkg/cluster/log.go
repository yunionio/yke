package cluster

import (
	"context"
	"fmt"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/templates"
	"yunion.io/x/yke/pkg/types"
)

const (
	DockerLogrotateConfigWriter = "docker-logrotate-writer"
	DockerLogrotateConfigPath   = "/etc/logrotate.d/docker-container"
)

func deployLogrotateConfig(ctx context.Context, uniqueHosts []*hosts.Host, graphDir string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	for _, host := range uniqueHosts {
		log.Debugf("Deploying docker logrotate config to host [%s]", host.Address)
		if err := doDeployLogrotateConfig(ctx, host, graphDir, alpineImage, prsMap); err != nil {
			return fmt.Errorf("Failed to deploy docker lograte config on node [%s]: %v", host.Address, err)
		}
	}
	return nil
}

func doDeployLogrotateConfig(ctx context.Context, host *hosts.Host, graphDir string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	if graphDir == "" {
		graphDir = "/var/lib/docker"
	}
	conf, err := templates.CompileTemplateFromMap(templates.DockerLogrotateConfig, map[string]string{
		"DockerGraphDir": graphDir,
	})
	if err != nil {
		return err
	}
	return host.WriteHostFile(ctx, DockerLogrotateConfigWriter, DockerLogrotateConfigPath, conf, alpineImage, prsMap)
}
