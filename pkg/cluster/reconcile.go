package cluster

import (
	"context"
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"

	"yunion.io/x/log"

	"yunion.io/x/yke/pkg/hosts"
	"yunion.io/x/yke/pkg/k8s"
	"yunion.io/x/yke/pkg/pki"
	"yunion.io/x/yke/pkg/services"
	"yunion.io/x/yke/pkg/types"
)

const (
	unschedulableEtcdTaint    = "node-role.kubernetes.io/etcd=true:NoExecute"
	unschedulableControlTaint = "node-role.kubernetes.io/controlplane=true:NoSchedule"
)

func ReconcileCluster(ctx context.Context, kubeCluster, currentCluster *Cluster, updateOnly bool) error {
	log.Infof("[reconcile] Reconciling cluster state")
	kubeCluster.UpdateWorkersOnly = updateOnly
	if currentCluster == nil {
		log.Infof("[reconcile] This is newly generated cluster")
		kubeCluster.UpdateWorkersOnly = false
		return nil
	}

	kubeClient, err := k8s.NewClient(kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport)
	if err != nil {
		return fmt.Errorf("Failed to initialize new kubernetes client: %v", err)
	}
	// sync node labels to define the toDelete labels
	syncLabels(ctx, currentCluster, kubeCluster)

	if err := reconcileEtcd(ctx, currentCluster, kubeCluster, kubeClient); err != nil {
		return fmt.Errorf("Failed to reconcile etcd plane: %v", err)
	}

	if err := reconcileWorker(ctx, currentCluster, kubeCluster, kubeClient); err != nil {
		return err
	}

	if err := reconcileControl(ctx, currentCluster, kubeCluster, kubeClient); err != nil {
		return err
	}
	// Handle service account token key issue
	kubeAPICert := currentCluster.Certificates[pki.KubeAPICertName]
	if currentCluster.Certificates[pki.ServiceAccountTokenKeyName].Key == nil {
		log.Infof("[certificates] Creating service account token key")
		currentCluster.Certificates[pki.ServiceAccountTokenKeyName] = pki.ToCertObject(pki.ServiceAccountTokenKeyName, pki.ServiceAccountTokenKeyName, "", kubeAPICert.Certificate, kubeAPICert.Key)
	}
	log.Infof("[reconcile] Reconciled cluster state successfully")
	return nil
}

func reconcileWorker(ctx context.Context, currentCluster, kubeCluster *Cluster, kubeClient *kubernetes.Clientset) error {
	// worker deleted first to avoid issues when worker+controller on same host
	log.Debugf("[reconcile] Check worker hosts to be deleted")
	wpToDelete := hosts.GetToDeleteHosts(currentCluster.WorkerHosts, kubeCluster.WorkerHosts, kubeCluster.InactiveHosts)
	for _, toDeleteHost := range wpToDelete {
		toDeleteHost.IsWorker = false
		if err := hosts.DeleteNode(ctx, toDeleteHost, kubeClient, toDeleteHost.IsControl, kubeCluster.CloudProvider.Name); err != nil {
			return fmt.Errorf("Failed to delete worker node %s from cluster", toDeleteHost.Address)
		}
		// attempting to clean services/files on the host
		if err := reconcileHost(ctx, toDeleteHost, true, false, currentCluster.SystemImages.Alpine, currentCluster.DockerDialerFactory, currentCluster.PrivateRegistriesMap, currentCluster.PrefixPath, currentCluster.Version); err != nil {
			log.Warningf("[reconcile] Couldn't clean up worker node [%s]: %v", toDeleteHost.Address, err)
			continue
		}
	}
	// attempt to remove unschedulable taint
	toAddHosts := hosts.GetToAddHosts(currentCluster.WorkerHosts, kubeCluster.WorkerHosts)
	for _, host := range toAddHosts {
		host.UpdateWorker = true
		if host.IsEtcd {
			host.ToDelTaints = append(host.ToDelTaints, unschedulableEtcdTaint)
		}
		if host.IsControl {
			host.ToDelTaints = append(host.ToDelTaints, unschedulableControlTaint)
		}
	}
	return nil
}

func reconcileControl(ctx context.Context, currentCluster, kubeCluster *Cluster, kubeClient *kubernetes.Clientset) error {
	log.Debugf("[reconcile] Check Control plane hosts to be deleted")
	selfDeleteAddress, err := getLocalConfigAddress(kubeCluster.LocalKubeConfigPath)
	if err != nil {
		return err
	}
	cpToDelete := hosts.GetToDeleteHosts(currentCluster.ControlPlaneHosts, kubeCluster.ControlPlaneHosts, kubeCluster.InactiveHosts)
	// move the current host in local kubeconfig to the end of the list
	for i, toDeleteHost := range cpToDelete {
		if toDeleteHost.Address == selfDeleteAddress {
			cpToDelete = append(cpToDelete[:i], cpToDelete[i+1:]...)
			cpToDelete = append(cpToDelete, toDeleteHost)
		}
	}

	if len(cpToDelete) == len(currentCluster.ControlPlaneHosts) {
		log.Infof("[reconcile] Deleting all current controlplane nodes, skipping deleting from k8s cluster")
		// rebuilding local admin config to enable saving cluster state
		if err := rebuildLocalAdminConfig(ctx, kubeCluster); err != nil {
			return err
		}
		return nil
	}

	for _, toDeleteHost := range cpToDelete {
		if err := cleanControlNode(ctx, kubeCluster, currentCluster, toDeleteHost); err != nil {
			return err
		}
	}
	// rebuilding local admin config to enable saving cluster state
	if err := rebuildLocalAdminConfig(ctx, kubeCluster); err != nil {
		return err
	}
	return nil
}

func reconcileHost(ctx context.Context, toDeleteHost *hosts.Host, worker, etcd bool, cleanerImage string, dialerFactory hosts.DialerFactory, prsMap map[string]types.PrivateRegistry, clusterPrefixPath string, clusterVersion string) error {
	if err := toDeleteHost.TunnelUp(ctx, dialerFactory, clusterPrefixPath, clusterVersion); err != nil {
		return fmt.Errorf("Not able to reach the host: %v", err)
	}
	if worker {
		if err := services.RemoveWorkerPlane(ctx, []*hosts.Host{toDeleteHost}, false); err != nil {
			return fmt.Errorf("Couldn't remove worker plane: %v", err)
		}
		if err := toDeleteHost.CleanUpWorkerHost(ctx, cleanerImage, prsMap); err != nil {
			return fmt.Errorf("Not able to clean the host: %v", err)
		}
	} else if etcd {
		if err := services.RemoveEtcdPlane(ctx, []*hosts.Host{toDeleteHost}, false); err != nil {
			return fmt.Errorf("Couldn't remove etcd plane: %v", err)
		}
		if err := toDeleteHost.CleanUpEtcdHost(ctx, cleanerImage, prsMap); err != nil {
			return fmt.Errorf("Not able to clean the host: %v", err)
		}
	} else {
		if err := services.RemoveControlPlane(ctx, []*hosts.Host{toDeleteHost}, false); err != nil {
			return fmt.Errorf("Couldn't remove control plane: %v", err)
		}
		if err := toDeleteHost.CleanUpControlHost(ctx, cleanerImage, prsMap); err != nil {
			return fmt.Errorf("Not able to clean the host: %v", err)
		}
	}
	return nil
}

func reconcileEtcd(ctx context.Context, currentCluster, kubeCluster *Cluster, kubeClient *kubernetes.Clientset) error {
	log.Infof("[reconcile] Check etcd hosts to be deleted")
	// get tls for the first current etcd host
	clientCert := cert.EncodeCertPEM(currentCluster.Certificates[pki.KubeNodeCertName].Certificate)
	clientkey := cert.EncodePrivateKeyPEM(currentCluster.Certificates[pki.KubeNodeCertName].Key)

	etcdToDelete := hosts.GetToDeleteHosts(currentCluster.EtcdHosts, kubeCluster.EtcdHosts, kubeCluster.InactiveHosts)
	for _, etcdHost := range etcdToDelete {
		if err := services.RemoveEtcdMember(ctx, etcdHost, kubeCluster.EtcdHosts, currentCluster.LocalConnDialerFactory, clientCert, clientkey); err != nil {
			log.Warningf("[reconcile] remove etcd meber:  %v", err)
			continue
		}
		if err := hosts.DeleteNode(ctx, etcdHost, kubeClient, etcdHost.IsControl, kubeCluster.CloudProvider.Name); err != nil {
			log.Warningf("Failed to delete etcd node %s from cluster: %v", etcdHost.Address, err)
			continue
		}
		// attempting to clean services/files on the host
		if err := reconcileHost(ctx, etcdHost, false, true, currentCluster.SystemImages.Alpine, currentCluster.DockerDialerFactory, currentCluster.PrivateRegistriesMap, currentCluster.PrefixPath, currentCluster.Version); err != nil {
			log.Warningf("[reconcile] Couldn't clean up etcd node [%s]: %v", etcdHost.Address, err)
			continue
		}
	}
	log.Infof("[reconcile] Check etcd hosts to be added")
	etcdToAdd := hosts.GetToAddHosts(currentCluster.EtcdHosts, kubeCluster.EtcdHosts)
	crtMap := currentCluster.Certificates
	var err error
	for _, etcdHost := range etcdToAdd {
		kubeCluster.UpdateWorkersOnly = false
		etcdHost.ToAddEtcdMember = true
		// Generate new certificate for the new etcd member
		crtMap, err = pki.RegenerateEtcdCertificate(
			ctx,
			crtMap,
			etcdHost,
			kubeCluster.EtcdHosts,
			kubeCluster.ClusterDomain,
			kubeCluster.KubernetesServiceIP)
		if err != nil {
			return err
		}
	}
	currentCluster.Certificates = crtMap
	for _, etcdHost := range etcdToAdd {
		// deploy certificates on new etcd host
		if err := pki.DeployCertificatesOnHost(ctx, etcdHost, currentCluster.Certificates, kubeCluster.SystemImages.CertDownloader, pki.CertPathPrefix, kubeCluster.PrivateRegistriesMap); err != nil {
			return err
		}

		// Check if the host already part of the cluster -- this will cover cluster with lost quorum
		isEtcdMember, err := services.IsEtcdMember(ctx, etcdHost, kubeCluster.EtcdHosts, currentCluster.LocalConnDialerFactory, clientCert, clientkey)
		if err != nil {
			return err
		}
		if !isEtcdMember {
			if err := services.AddEtcdMember(ctx, etcdHost, kubeCluster.EtcdHosts, currentCluster.LocalConnDialerFactory, clientCert, clientkey); err != nil {
				return err
			}
		}
		etcdHost.ToAddEtcdMember = false
		kubeCluster.setReadyEtcdHosts()

		etcdNodePlanMap := make(map[string]types.ConfigNodePlan)
		for _, etcdReadyHost := range kubeCluster.EtcdReadyHosts {
			etcdNodePlanMap[etcdReadyHost.Address] = BuildKEConfigNodePlan(ctx, kubeCluster, etcdReadyHost, etcdReadyHost.DockerInfo)
		}
		// this will start the newly added etcd node and make sure it started correctly before restarting other node
		// https://github.com/etcd-io/etcd/blob/master/Documentation/op-guide/runtime-configuration.md#add-a-new-member
		if err := services.ReloadEtcdCluster(ctx, kubeCluster.EtcdReadyHosts, etcdHost, currentCluster.LocalConnDialerFactory, clientCert, clientkey, currentCluster.PrivateRegistriesMap, etcdNodePlanMap, kubeCluster.SystemImages.Alpine); err != nil {
			return err
		}
	}
	return nil
}

func syncLabels(ctx context.Context, currentCluster, kubeCluster *Cluster) {
	currentHosts := hosts.GetUniqueHostList(currentCluster.EtcdHosts, currentCluster.ControlPlaneHosts, currentCluster.WorkerHosts)
	configHosts := hosts.GetUniqueHostList(kubeCluster.EtcdHosts, kubeCluster.ControlPlaneHosts, kubeCluster.WorkerHosts)
	for _, host := range configHosts {
		for _, currentHost := range currentHosts {
			if host.Address == currentHost.Address {
				for k, v := range currentHost.Labels {
					if _, ok := host.Labels[k]; !ok {
						host.ToDelLabels[k] = v
					}
				}
				break
			}
		}
	}
}

func (c *Cluster) setReadyEtcdHosts() {
	c.EtcdReadyHosts = []*hosts.Host{}
	for _, host := range c.EtcdHosts {
		if !host.ToAddEtcdMember {
			c.EtcdReadyHosts = append(c.EtcdReadyHosts, host)
			host.ExistingEtcdCluster = true
		}
	}
}

func cleanControlNode(ctx context.Context, kubeCluster, currentCluster *Cluster, toDeleteHost *hosts.Host) error {
	kubeClient, err := k8s.NewClient(kubeCluster.LocalKubeConfigPath, kubeCluster.K8sWrapTransport)
	if err != nil {
		return fmt.Errorf("Failed to initialize new kubernetes client: %v", err)
	}
	// if I am deleting a node that's already in the config, it's probably being replaced and I shouldn't remove it from k8s
	if !hosts.IsNodeInList(toDeleteHost, kubeCluster.ControlPlaneHosts) {
		if err := hosts.DeleteNode(ctx, toDeleteHost, kubeClient, toDeleteHost.IsWorker, kubeCluster.CloudConfigFile); err != nil {
			return fmt.Errorf("Failed to delete controlplane node [%s] from cluster: %v", toDeleteHost.Address, err)
		}
	}
	// attempting to clean services/files on the host
	if err := reconcileHost(ctx, toDeleteHost, false, false, currentCluster.SystemImages.Alpine, currentCluster.DockerDialerFactory, currentCluster.PrivateRegistriesMap, currentCluster.PrefixPath, currentCluster.Version); err != nil {
		log.Warningf("[reconcile] Couldn't clean up controlplane node [%s]: %v", toDeleteHost.Address, err)
	}
	return nil
}
