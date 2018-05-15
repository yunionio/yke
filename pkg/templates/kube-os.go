package templates

const KubectlOsAuthTemplate = `
apiVersion: v1
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: {{.KubeAPIServerURL}}
  name: yunioncluster
contexts:
- context:
    cluster: yunioncluster
    user: openstackuser
  name: openstackuser@kubernetes
current-context: openstackuser@kubernetes
kind: Config
preferences: {}
users:
- name: openstackuser
  user:
    as-user-extra: {}
    auth-provider:
      config:
        ttl: 10m0s
      name: openstack`
