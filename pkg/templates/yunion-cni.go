package templates

const YunionHostAgentSystemdTemplate = `
[Unit]
Description=Yunion Cloud Host CNI Agent
Documentation=http://doc.yunionyun.com
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/opt/cni/bin/yunion-host-agent
KillMode=process

[Install]
WantedBy=multi-user.target
`

const YunionCNITemplate = `
{{if eq .RBACConfig "rbac"}}
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: yunion
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: yunion
subjects:
- kind: ServiceAccount
  name: yunion
  namespace: kube-system
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: yunion
rules:
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - nodes
    verbs:
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - nodes/status
    verbs:
      - patch
{{- end}}
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: yunion-config
  namespace: kube-system
data:
  cni-conf.json: |
    {
      "cniVersion": "0.3.1",
      "name": "yunion-cni",
      "type": "yunion-bridge",
      "isDefaultGateway": false,
      "bridge": "{{.YunionBridge}}",
      "cluster_ip_range": "{{.ClusterCIDR}}",
      "ipam": {
        "type": "yunion-ipam",
        "auth_url": "{{.YunionAuthURL}}",
        "admin_user": "{{.YunionAdminUser}}",
        "admin_password": "{{.YunionAdminPasswd}}",
        "admin_project": "{{.YunionAdminProject}}",
        "timeout": 30,
        "cluster": "{{.YunionKubeCluster}}",
        "region": "{{.YunionRegion}}"
      }
    }
---
kind: DaemonSet
apiVersion: extensions/v1beta1
metadata:
  name: yunion
  namespace: kube-system
  labels:
    k8s-app: yunion
spec:
  template:
    metadata:
      labels:
        k8s-app: yunion
    spec:
      serviceAccountName: yunion
      hostNetwork: true
      containers:
        # Runs yunion/cni container on each Kubernetes node.
        # This container installs the Yunion CNI binaries
        # and CNI network config file on each node.
        - name: install-cni
          image: {{.CNIImage}}
          command: ["/install-cni.sh"]
          env:
          # The CNI network config to install on each node.
          - name: CNI_NETWORK_CONFIG
            valueFrom:
              configMapKeyRef:
                name: yunion-config
                key: cni-conf.json
          - name: CNI_CONF_NAME
            value: "10-yunion.conf"
          volumeMounts:
          - mountPath: /host/opt/cni/bin
            name: host-cni-bin
          - mountPath: /host/etc/cni/net.d
            name: host-cni-net
      volumes:
        - name: host-cni-net
          hostPath:
            path: /etc/cni/net.d
        - name: yunion-config
          configMap:
            name: yunion-config
        - name: host-cni-bin
          hostPath:
            path: /opt/cni/bin
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: yunion
  namespace: kube-system`
