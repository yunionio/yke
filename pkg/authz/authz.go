package authz

import (
	"context"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/k8s"
	"yunion.io/x/yke/pkg/templates"
)

func ApplyJobDeployerServiceAccount(ctx context.Context, kubeConfigPath string, k8sWrapTransport k8s.WrapTransport) error {
	log.Infof("[authz] Creating rke-job-deployer ServiceAccount")
	k8sClient, err := k8s.NewClient(kubeConfigPath, k8sWrapTransport)
	if err != nil {
		return err
	}
	if err := k8s.UpdateClusterRoleBindingFromYaml(k8sClient, templates.JobDeployerClusterRoleBinding); err != nil {
		return err
	}
	if err := k8s.UpdateServiceAccountFromYaml(k8sClient, templates.JobDeployerServiceAccount); err != nil {
		return err
	}
	log.Infof("[authz] rke-job-deployer ServiceAccount created successfully")
	return nil
}

func ApplySystemNodeClusterRoleBinding(ctx context.Context, kubeConfigPath string, k8sWrapTransport k8s.WrapTransport) error {
	log.Infof("[authz] Creating system:node ClusterRoleBinding")
	k8sClient, err := k8s.NewClient(kubeConfigPath, k8sWrapTransport)
	if err != nil {
		return err
	}
	if err := k8s.UpdateClusterRoleBindingFromYaml(k8sClient, templates.SystemNodeClusterRoleBinding); err != nil {
		return err
	}
	log.Infof("[authz] system:node ClusterRoleBinding created successfully")
	return nil
}
