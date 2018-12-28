package templates

const YunionCloudProviderTemplate = `
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloud-controller-manager
  namespace: kube-system
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:cloud-controller-manager
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: cloud-controller-manager
  namespace: kube-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: yunion-cloud-controller-manager
  annotations:
     scheduler.alpha.kubernetes.io/critical-pod: ''
  name: yunion-cloud-controller-manager
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: yunion-cloud-controller-manager
  template:
    metadata:
      labels:
        k8s-app: yunion-cloud-controller-manager
        lxcfs: "false"
    spec:
      hostNetwork: true
      serviceAccountName: cloud-controller-manager
      tolerations:
      # this is required so CCM can bootstrap itself
      - key: node.cloudprovider.kubernetes.io/uninitialized
        value: "true"
        effect: NoSchedule
      # cloud controller manages should be able to run on masters
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      - key: node-role.kubernetes.io/controlplane
        effect: NoSchedule
      # this is to restrict CCM to only run on master nodes
      # the node selector may vary depending on your cluster setup
      containers:
      - name: cloud-controller-manager
        image: {{.CloudProviderImage}}
        command:
        - /yunion-cloud-controller-manager
        - --v=2
        - --leader-elect=true
        - --configure-cloud-routes=false
        - --cloud-config=/etc/kubernetes/cloud-config.json
        - --use-service-account-credentials=false
        volumeMounts:
        - mountPath: /etc/kubernetes
          name: kubernetes-config
      volumes:
      - hostPath:
          path: /etc/kubernetes
          type: Directory
        name: kubernetes-config`
