package templates

const YunionCSITemplate = `
---

### Yunion csi StorageClass

apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: csi-yunion
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: csi-yunionplugin
reclaimPolicy: Delete

---

### Attacher plugin

apiVersion: v1
kind: ServiceAccount
metadata:
  name: csi-attacher

---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: external-attacher-runner
rules:
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments"]
    verbs: ["get", "list", "watch", "update"]

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: csi-attacher-role
subjects:
  - kind: ServiceAccount
    name: csi-attacher
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: external-attacher-runner
  apiGroup: rbac.authorization.k8s.io

---
kind: Service
apiVersion: v1
metadata:
  name: csi-yunionplugin-attacher
  labels:
    app: csi-yunionplugin-attacher
spec:
  selector:
    app: csi-yunionplugin-attacher
  ports:
    - name: dummy
      port: 12345

---
kind: StatefulSet
apiVersion: apps/v1beta1
metadata:
  name: csi-yunionplugin-attacher
spec:
  serviceName: "csi-yunionplugin-attacher"
  replicas: 1
  template:
    metadata:
      labels:
        app: csi-yunionplugin-attacher
    spec:
      serviceAccount: csi-attacher
      hostNetwork: true
      containers:
        - name: csi-yunionplugin-attacher
          image: {{.CSIAttacher}}
          args:
            - "--v=5"
            - "--csi-address=$(ADDRESS)"
          env:
            - name: ADDRESS
              value: /var/lib/kubelet/plugins/csi-yunionplugin/csi.sock
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/kubelet/plugins/csi-yunionplugin
      volumes:
        - name: socket-dir
          hostPath:
            path: /var/lib/kubelet/plugins/csi-yunionplugin
            type: DirectoryOrCreate
---

### Provisioner
apiVersion: v1
kind: ServiceAccount
metadata:
  name: csi-provisioner

---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: external-provisioner-runner
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "create", "delete"]
  - apiGroups: [""]
    resources: ["persistentvolumeclaims"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch", "create", "update", "patch"]
  - apiGroups: [""]
    resources: ["endpoints"]
    verbs: ["list", "watch", "create", "update", "get"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshots"]
    verbs: ["get", "list"]
  - apiGroups: ["snapshot.storage.k8s.io"]
    resources: ["volumesnapshotcontents"]
    verbs: ["get", "list"]

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: csi-provisioner-role
subjects:
  - kind: ServiceAccount
    name: csi-provisioner
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: external-provisioner-runner
  apiGroup: rbac.authorization.k8s.io

---
kind: Service
apiVersion: v1
metadata:
  name: csi-yunionplugin-provisioner
  labels:
    app: csi-yunionplugin-provisioner
spec:
  selector:
    app: csi-yunionplugin-provisioner
  ports:
    - name: dummy
      port: 12345

---
kind: StatefulSet
apiVersion: apps/v1beta1
metadata:
  name: csi-yunionplugin-provisioner
spec:
  serviceName: "csi-yunionplugin-provisioner"
  replicas: 1
  template:
    metadata:
      labels:
        app: csi-yunionplugin-provisioner
    spec:
      serviceAccount: csi-provisioner
      hostNetwork: true
      containers:
        - name: csi-provisioner
          image: {{.CSIProvisioner}}
          args:
            - "--provisioner=csi-yunionplugin"
            - "--csi-address=$(ADDRESS)"
            - "--v=5"
            - "--connection-timeout=30s"
          env:
            - name: ADDRESS
              value: /var/lib/kubelet/plugins/csi-yunionplugin/csi.sock
          imagePullPolicy: "IfNotPresent"
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/kubelet/plugins/csi-yunionplugin
      volumes:
        - name: socket-dir
          hostPath:
            path: /var/lib/kubelet/plugins/csi-yunionplugin
            type: DirectoryOrCreate

---

### Plugin

apiVersion: v1
kind: ServiceAccount
metadata:
  name: csi-nodeplugin

---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: csi-nodeplugin
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["get", "list", "update"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["volumeattachments"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["csi.storage.k8s.io"]
    resources: ["csidrivers"]
    verbs: ["get", "list", "watch", "update"]
  - apiGroups: ["csi.storage.k8s.io"]
    resources: ["csinodeinfos"]
    verbs: ["get", "list", "watch", "update"]

---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: csi-nodeplugin
subjects:
  - kind: ServiceAccount
    name: csi-nodeplugin
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: csi-nodeplugin
  apiGroup: rbac.authorization.k8s.io

---
kind: DaemonSet
apiVersion: apps/v1beta2
metadata:
  name: csi-yunionplugin
spec:
  selector:
    matchLabels:
      app: csi-yunionplugin
  template:
    metadata:
      labels:
        app: csi-yunionplugin
    spec:
      serviceAccount: csi-nodeplugin
      hostNetwork: true
      # to use e.g. Rook orchestrated cluster, and mons' FQDN is
      # resolved through k8s service, set dns policy to cluster first
      dnsPolicy: ClusterFirstWithHostNet
      containers:
        - name: driver-registrar
          image: {{.CSIRegistrar}}
          args:
            - "--v=5"
            - "--csi-address=$(ADDRESS)"
            - "--mode=node-register"
            #- --pod-info-mount-version="v1"
            - "--kubelet-registration-path=$(DRIVER_REG_SOCK_PATH)"
          env:
            - name: ADDRESS
              value: /var/lib/kubelet/plugins/csi-yunionplugin/csi.sock
            - name: DRIVER_REG_SOCK_PATH
              value: /var/lib/kubelet/plugins/csi-yunionplugin/csi.sock
            - name: KUBE_NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          volumeMounts:
            - name: socket-dir
              mountPath: /var/lib/kubelet/plugins/csi-yunionplugin
            - name: registration-dir
              mountPath: /registration
        - name: csi-yunionplugin
          securityContext:
            privileged: true
            capabilities:
              add: ["SYS_ADMIN"]
            allowPrivilegeEscalation: true
          image: {{.CSIImage}}
          args :
            - "--nodeid=$(NODE_ID)"
            - "--endpoint=$(CSI_ENDPOINT)"
            - "--v=5"
            - "--drivername=csi-yunionplugin"
            - "--authUrl={{.YunionAuthURL}}"
            - "--adminUser={{.YunionAdminUser}}"
            - "--adminPassword={{.YunionAdminPasswd}}"
            - "--adminProject={{.YunionAdminProject}}"
            - "--region={{.YunionRegion}}"
          env:
            - name: HOST_ROOTFS
              value: "/host"
            - name: NODE_ID
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: CSI_ENDPOINT
              value: unix://var/lib/kubelet/plugins/csi-yunionplugin/csi.sock
          imagePullPolicy: "Always"
          volumeMounts:
            - name: plugin-dir
              mountPath: /var/lib/kubelet/plugins/csi-yunionplugin
            - name: pods-mount-dir
              mountPath: /var/lib/kubelet/pods
              mountPropagation: "Bidirectional"
            - mountPath: /dev
              name: host-dev
            - mountPath: /host
              name: host-rootfs
            - mountPath: /sys
              name: host-sys
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
            - mountPath: /opt/cloud/workspace
              name: yunion-workspace
      volumes:
        - name: plugin-dir
          hostPath:
            path: /var/lib/kubelet/plugins/csi-yunionplugin
            type: DirectoryOrCreate
        - name: registration-dir
          hostPath:
            path: /var/lib/kubelet/plugins/
            type: Directory
        - name: pods-mount-dir
          hostPath:
            path: /var/lib/kubelet/pods
            type: Directory
        - name: socket-dir
          hostPath:
            path: /var/lib/kubelet/plugins/csi-yunionplugin
            type: DirectoryOrCreate
        - name: host-dev
          hostPath:
            path: /dev
        - name: host-rootfs
          hostPath:
            path: /
        - name: host-sys
          hostPath:
            path: /sys
        - name: lib-modules
          hostPath:
            path: /lib/modules
        - name: yunion-workspace
          hostPath:
            path: /opt/cloud/workspace`
