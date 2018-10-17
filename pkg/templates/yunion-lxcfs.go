package templates

const YunionLXCFSTemplate = `
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: lxcfs-initializer-default
  namespace: kube-system
rules:
- apiGroups: ["*"]
  resources: ["pods"]
  verbs: ["initialize", "update", "patch", "watch", "list"]

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lxcfs-initializer-service-account
  namespace: kube-system

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: lxcfs-initializer-role-binding
subjects:
- kind: ServiceAccount
  name: lxcfs-initializer-service-account
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: lxcfs-initializer-default
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  initializers:
    pending: []
  labels:
    app: lxcfs-initializer
    lxcfs: "false"
  name: lxcfs-initializer
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: lxcfs-initializer
        lxcfs: "false"
      name: lxcfs-initializer
    spec:
      serviceAccountName: lxcfs-initializer-service-account
      containers:
        - name: lxcfs-initializer
          image: {{.LXCFSInitImage}}
          imagePullPolicy: Always
          args:
            - "-annotation=initializer.kubernetes.io/lxcfs"
            - "-require-annotation=false"

---
apiVersion: admissionregistration.k8s.io/v1alpha1
kind: InitializerConfiguration
metadata:
  name: lxcfs.initializer
initializers:
  - name: lxcfs.initializer.kubernetes.io
    rules:
      - apiGroups:
          - "*"
        apiVersions:
          - "*"
        resources:
          - pods`
