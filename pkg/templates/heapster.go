package templates

const HeapsterTemplate = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: heapster
  namespace: kube-system

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: heapster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:heapster
subjects:
  - kind: ServiceAccount
    name: heapster
  namespace: kube-system

---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: heapster-apiserver
  namespace: kube-system
  labels:
    k8s-app: heapster
    module: apiserver
    version: v6
spec:
  template:
    metadata:
      labels:
        k8s-app: heapster
        module: apiserver
        version: v6
    spec:
      serviceAccountName: heapster
      hostNetwork: true
      containers:
      - name: heapster
        image: {{ .HeapsterImage }}
        command:
        - /heapster
        - --source=kubernetes.summary_api
        - --sink={{ .InfluxdbUrl }}
        - --stats_resolution=1m
        volumeMounts:
        - mountPath: /etc/ssl/certs
          name: ssl-certs
          readOnly: true
      volumes:
      - name: ssl-certs
        hostPath:
          path: /etc/ssl/certs
---
apiVersion: v1
kind: Service
metadata:
  labels:
    task: monitoring
    # For use as a Cluster add-on (https://github.com/kubernetes/kubernetes/tree/master/cluster/addons)
    # If you are NOT using this as an addon, you should comment out this line.
    kubernetes.io/cluster-service: 'true'
    kubernetes.io/name: Heapster
  name: heapster
  namespace: kube-system
spec:
  ports:
  - port: 80
    targetPort: 8082
  selector:
    k8s-app: heapster`
