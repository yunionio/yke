package templates

const YunionCloudMonitorTemplate = `
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  labels:
    app: cloudmon
  name: cloudmon
  namespace: kube-system
spec:
  template:
    metadata:
      labels:
        app: cloudmon
    spec:
      hostNetwork: true
      containers:
      - name: cloudmon
        image: {{.YunionCloudMonitorImage}}
        env:
        - name: JAVA_OPTIONS
          value: "-Dconf=/deployments/config/config.properties"
        volumeMounts:
        - mountPath: /deployments/config
          name: config
      volumes:
      - name: config
        configMap:
          name: cloudmon

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cloudmon
  namespace: kube-system
data:
  application.properties: |
    debug=false
    trace=false
    logging.level.com.yunion=INFO

    yunion.rc.auth.url={{.YunionAuthURL}}
    yunion.rc.auth.domain={{.YunionDomain}}
    yunion.rc.auth.username={{.YunionAdminUser}}
    yunion.rc.auth.password={{.YunionAdminPasswd}}
    yunion.rc.auth.project={{.YunionAdminProject}}
    yunion.rc.auth.region={{.YunionRegion}}
    yunion.rc.auth.cache-size=500
    yunion.rc.auth.timeout=1000
    yunion.rc.auth.debug=true
    yunion.rc.auth.insecure=false
    yunion.rc.auth.refresh-interval=300000

    yunion.rc.async-job.initial-delay=2000
    yunion.rc.async-job.fixed-rate=300000
    yunion.rc.async-job.fixed-thread-pool=10

    yunion.rc.influxdb.url={{.InfluxdbUrl}}
    yunion.rc.influxdb.database=cloudmon
    yunion.rc.influxdb.measurement=instance

    yunion.rc.metrics.ins.providers=Aliyun,Azure
    yunion.rc.metrics.eip.providers=Aliyun`
