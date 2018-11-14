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

const (
	WebhookConfigDeployer = "webhook-config-deployer"
	WebhookConfigPath     = "/etc/kubernetes/webhook.kubeconfig"
	WebhookServiceName    = "webhook"
	WebhookConfigEnv      = "YKE_WEBHOOK_CONFIG"
)

const (
	SchedulerConfigWriter = "scheduler-config-writer"
	SchedulerConfigPath   = "/etc/kubernetes/k8s-sched-policy.json"
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

func deployWebhookConfig(ctx context.Context, uniqueHosts []*hosts.Host, alpineImage string, webhookConfig string, prsMap map[string]types.PrivateRegistry) error {
	for _, host := range uniqueHosts {
		log.Infof("[%s] Deploying webhook config file to node [%s]", WebhookServiceName, host.Address)
		if err := doDeployWebhookConfigFile(ctx, host, webhookConfig, alpineImage, prsMap); err != nil {
			return fmt.Errorf("Failed to deploy webhook config file on node [%s]: %v", host.Address, err)
		}
	}
	return nil
}

func doDeployWebhookConfigFile(ctx context.Context, host *hosts.Host, webhookConfig string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	return host.WriteHostFile(ctx, WebhookConfigDeployer, WebhookConfigPath, webhookConfig, alpineImage, prsMap)
}

func deploySchedulerConfig(ctx context.Context, uniqueHosts []*hosts.Host, alpineImage string, schedulerConfig string, prsMap map[string]types.PrivateRegistry) error {
	for _, host := range uniqueHosts {
		log.Infof("[%s] Deploying scheduler policy config file to node [%s]", SchedulerConfigWriter, host.Address)
		if err := doDeploySchedulerConfig(ctx, host, schedulerConfig, alpineImage, prsMap); err != nil {
			return fmt.Errorf("Failed to deploy scheduler config file on node [%s]: %v", host.Address, err)
		}
	}
	return nil
}

func doDeploySchedulerConfig(ctx context.Context, host *hosts.Host, schedulerConfig string, alpineImage string, prsMap map[string]types.PrivateRegistry) error {
	return host.WriteHostFile(ctx, SchedulerConfigWriter, SchedulerConfigPath, schedulerConfig, alpineImage, prsMap)
}
