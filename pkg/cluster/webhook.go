package cluster

import (
	"context"
	"fmt"

	"yunion.io/yke/pkg/hosts"
	"yunion.io/yke/pkg/types"
	"yunion.io/yunioncloud/pkg/log"
)

const (
	WebhookConfigDeployer = "webhook-config-deployer"
	WebhookConfigPath     = "/etc/kubernetes/webhook.kubeconfig"
	WebhookServiceName    = "webhook"
	WebhookConfigEnv      = "YKE_WEBHOOK_CONFIG"
)

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
