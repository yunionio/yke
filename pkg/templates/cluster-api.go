package templates

const ClusterAPITemplate = `
---

### cluster_v1alpha1_cluster.yaml ###

apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  creationTimestamp: null
  labels:
    controller-tools.k8s.io: "1.0"
  name: clusters.cluster.k8s.io
spec:
  group: cluster.k8s.io
  names:
    kind: Cluster
    plural: clusters
  scope: Namespaced
  subresources:
    status: {}
  validation:
    openAPIV3Schema:
      properties:
        apiVersion:
          description: 'APIVersion defines the versioned schema of this representation
            of an object. Servers should convert recognized schemas to the latest
            internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources'
          type: string
        kind:
          description: 'Kind is a string value representing the REST resource this
            object represents. Servers may infer this from the endpoint the client
            submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds'
          type: string
        metadata:
          type: object
        spec:
          properties:
            clusterNetwork:
              description: Cluster network configuration
              properties:
                pods:
                  description: The network ranges from which Pod networks are allocated.
                  properties:
                    cidrBlocks:
                      items:
                        type: string
                      type: array
                  required:
                  - cidrBlocks
                  type: object
                serviceDomain:
                  description: Domain name for services.
                  type: string
                services:
                  description: The network ranges from which service VIPs are allocated.
                  properties:
                    cidrBlocks:
                      items:
                        type: string
                      type: array
                  required:
                  - cidrBlocks
                  type: object
              required:
              - services
              - pods
              - serviceDomain
              type: object
            providerSpec:
              description: Provider-specific serialized configuration to use during
                cluster creation. It is recommended that providers maintain their
                own versioned API types that should be serialized/deserialized from
                this field.
              properties:
                value:
                  description: Value is an inlined, serialized representation of the
                    resource configuration. It is recommended that providers maintain
                    their own versioned API types that should be serialized/deserialized
                    from this field, akin to component config.
                  type: object
                valueFrom:
                  description: Source for the provider configuration. Cannot be used
                    if value is not empty.
                  properties:
                    machineClass:
                      description: The machine class from which the provider config
                        should be sourced.
                      properties:
                        provider:
                          description: Provider is the name of the cloud-provider
                            which MachineClass is intended for.
                          type: string
                      type: object
                  type: object
              type: object
          required:
          - clusterNetwork
          type: object
        status:
          properties:
            apiEndpoints:
              description: APIEndpoint represents the endpoint to communicate with
                the IP.
              items:
                properties:
                  host:
                    description: The hostname on which the API server is serving.
                    type: string
                  port:
                    description: The port on which the API server is serving.
                    format: int64
                    type: integer
                required:
                - host
                - port
                type: object
              type: array
            errorMessage:
              description: If set, indicates that there is a problem reconciling the
                state, and will be set to a descriptive error message.
              type: string
            errorReason:
              description: If set, indicates that there is a problem reconciling the
                state, and will be set to a token value suitable for programmatic
                interpretation.
              type: string
            providerStatus:
              description: Provider-specific status. It is recommended that providers
                maintain their own versioned API types that should be serialized/deserialized
                from this field.
              type: object
          type: object
  version: v1alpha1
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []

---

### cluster_v1alpha1_machine.yaml ###

apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  creationTimestamp: null
  labels:
    controller-tools.k8s.io: "1.0"
  name: machines.cluster.k8s.io
spec:
  group: cluster.k8s.io
  names:
    kind: Machine
    plural: machines
  scope: Namespaced
  subresources:
    status: {}
  validation:
    openAPIV3Schema:
      properties:
        apiVersion:
          description: 'APIVersion defines the versioned schema of this representation
            of an object. Servers should convert recognized schemas to the latest
            internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources'
          type: string
        kind:
          description: 'Kind is a string value representing the REST resource this
            object represents. Servers may infer this from the endpoint the client
            submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds'
          type: string
        metadata:
          type: object
        spec:
          properties:
            configSource:
              description: ConfigSource is used to populate in the associated Node
                for dynamic kubelet config. This field already exists in Node, so
                any updates to it in the Machine spec will be automatically copied
                to the linked NodeRef from the status. The rest of dynamic kubelet
                config support should then work as-is.
              type: object
            metadata:
              description: ObjectMeta will autopopulate the Node created. Use this
                to indicate what labels, annotations, name prefix, etc., should be
                used when creating the Node.
              type: object
            providerID:
              description: ProviderID is the identification ID of the machine provided
                by the provider. This field must match the provider ID as seen on
                the node object corresponding to this machine. This field is required
                by higher level consumers of cluster-api. Example use case is cluster
                autoscaler with cluster-api as provider. Clean-up login in the autoscaler
                compares machines v/s nodes to find out machines at provider which
                could not get registered as Kubernetes nodes. With cluster-api as
                a generic out-of-tree provider for autoscaler, this field is required
                by autoscaler to be able to have a provider view of the list of machines.
                Another list of nodes is queries from the k8s apiserver and then comparison
                is done to find out unregistered machines and are marked for delete.
                This field will be set by the actuators and consumed by higher level
                entities like autoscaler  who will be interfacing with cluster-api
                as generic provider.
              type: string
            providerSpec:
              description: ProviderSpec details Provider-specific configuration to
                use during node creation.
              properties:
                value:
                  description: Value is an inlined, serialized representation of the
                    resource configuration. It is recommended that providers maintain
                    their own versioned API types that should be serialized/deserialized
                    from this field, akin to component config.
                  type: object
                valueFrom:
                  description: Source for the provider configuration. Cannot be used
                    if value is not empty.
                  properties:
                    machineClass:
                      description: The machine class from which the provider config
                        should be sourced.
                      properties:
                        provider:
                          description: Provider is the name of the cloud-provider
                            which MachineClass is intended for.
                          type: string
                      type: object
                  type: object
              type: object
            taints:
              description: Taints is the full, authoritative list of taints to apply
                to the corresponding Node. This list will overwrite any modifications
                made to the Node on an ongoing basis.
              items:
                type: object
              type: array
            versions:
              description: Versions of key software to use. This field is optional
                at cluster creation time, and omitting the field indicates that the
                cluster installation tool should select defaults for the user. These
                defaults may differ based on the cluster installer, but the tool should
                populate the values it uses when persisting Machine objects. A Machine
                spec missing this field at runtime is invalid.
              properties:
                controlPlane:
                  description: ControlPlane is the semantic version of the Kubernetes
                    control plane to run. This should only be populated when the machine
                    is a control plane.
                  type: string
                kubelet:
                  description: Kubelet is the semantic version of kubelet to run
                  type: string
              required:
              - kubelet
              type: object
          required:
          - providerSpec
          type: object
        status:
          properties:
            addresses:
              description: Addresses is a list of addresses assigned to the machine.
                Queried from cloud provider, if available.
              items:
                type: object
              type: array
            conditions:
              description: 'Conditions lists the conditions synced from the node conditions
                of the corresponding node-object. Machine-controller is responsible
                for keeping conditions up-to-date. MachineSet controller will be taking
                these conditions as a signal to decide if machine is healthy or needs
                to be replaced. Refer: https://kubernetes.io/docs/concepts/architecture/nodes/#condition'
              items:
                type: object
              type: array
            errorMessage:
              description: ErrorMessage will be set in the event that there is a terminal
                problem reconciling the Machine and will contain a more verbose string
                suitable for logging and human consumption.  This field should not
                be set for transitive errors that a controller faces that are expected
                to be fixed automatically over time (like service outages), but instead
                indicate that something is fundamentally wrong with the Machine's
                spec or the configuration of the controller, and that manual intervention
                is required. Examples of terminal errors would be invalid combinations
                of settings in the spec, values that are unsupported by the controller,
                or the responsible controller itself being critically misconfigured.  Any
                transient errors that occur during the reconciliation of Machines
                can be added as events to the Machine object and/or logged in the
                controller's output.
              type: string
            errorReason:
              description: ErrorReason will be set in the event that there is a terminal
                problem reconciling the Machine and will contain a succinct value
                suitable for machine interpretation.  This field should not be set
                for transitive errors that a controller faces that are expected to
                be fixed automatically over time (like service outages), but instead
                indicate that something is fundamentally wrong with the Machine's
                spec or the configuration of the controller, and that manual intervention
                is required. Examples of terminal errors would be invalid combinations
                of settings in the spec, values that are unsupported by the controller,
                or the responsible controller itself being critically misconfigured.  Any
                transient errors that occur during the reconciliation of Machines
                can be added as events to the Machine object and/or logged in the
                controller's output.
              type: string
            lastOperation:
              description: LastOperation describes the last-operation performed by
                the machine-controller. This API should be useful as a history in
                terms of the latest operation performed on the specific machine. It
                should also convey the state of the latest-operation for example if
                it is still on-going, failed or completed successfully.
              properties:
                description:
                  description: Description is the human-readable description of the
                    last operation.
                  type: string
                lastUpdated:
                  description: LastUpdated is the timestamp at which LastOperation
                    API was last-updated.
                  format: date-time
                  type: string
                state:
                  description: State is the current status of the last performed operation.
                    E.g. Processing, Failed, Successful etc
                  type: string
                type:
                  description: Type is the type of operation which was last performed.
                    E.g. Create, Delete, Update etc
                  type: string
              type: object
            lastUpdated:
              description: LastUpdated identifies when this status was last observed.
              format: date-time
              type: string
            nodeRef:
              description: NodeRef will point to the corresponding Node if it exists.
              type: object
            phase:
              description: Phase represents the current phase of machine actuation.
                E.g. Pending, Running, Terminating, Failed etc.
              type: string
            providerStatus:
              description: ProviderStatus details a Provider-specific status. It is
                recommended that providers maintain their own versioned API types
                that should be serialized/deserialized from this field.
              type: object
            versions:
              description: 'Versions specifies the current versions of software on
                the corresponding Node (if it exists). This is provided for a few
                reasons:  1) It is more convenient than checking the NodeRef, traversing
                it to    the Node, and finding the appropriate field in Node.Status.NodeInfo    (which
                uses different field names and formatting). 2) It removes some of
                the dependency on the structure of the Node,    so that if the structure
                of Node.Status.NodeInfo changes, only    machine controllers need
                to be updated, rather than every client    of the Machines API. 3)
                There is no other simple way to check the control plane    version.
                A client would have to connect directly to the apiserver    running
                on the target node in order to find out its version.'
              properties:
                controlPlane:
                  description: ControlPlane is the semantic version of the Kubernetes
                    control plane to run. This should only be populated when the machine
                    is a control plane.
                  type: string
                kubelet:
                  description: Kubelet is the semantic version of kubelet to run
                  type: string
              required:
              - kubelet
              type: object
          type: object
  version: v1alpha1
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []

---

### cluster_v1alpha1_machineclass.yaml ###

apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  creationTimestamp: null
  labels:
    controller-tools.k8s.io: "1.0"
  name: machineclasses.cluster.k8s.io
spec:
  group: cluster.k8s.io
  names:
    kind: MachineClass
    plural: machineclasses
  scope: Namespaced
  validation:
    openAPIV3Schema:
      properties:
        apiVersion:
          description: 'APIVersion defines the versioned schema of this representation
            of an object. Servers should convert recognized schemas to the latest
            internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources'
          type: string
        kind:
          description: 'Kind is a string value representing the REST resource this
            object represents. Servers may infer this from the endpoint the client
            submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds'
          type: string
        metadata:
          type: object
        providerSpec:
          description: Provider-specific configuration to use during node creation.
          type: object
      required:
      - providerSpec
  version: v1alpha1
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
---

### cluster_v1alpha1_machinedeployment.yaml ###

apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  creationTimestamp: null
  labels:
    controller-tools.k8s.io: "1.0"
  name: machinedeployments.cluster.k8s.io
spec:
  group: cluster.k8s.io
  names:
    kind: MachineDeployment
    plural: machinedeployments
  scope: Namespaced
  subresources:
    scale:
      labelSelectorPath: .status.labelSelector
      specReplicasPath: .spec.replicas
      statusReplicasPath: .status.replicas
    status: {}
  validation:
    openAPIV3Schema:
      properties:
        apiVersion:
          description: 'APIVersion defines the versioned schema of this representation
            of an object. Servers should convert recognized schemas to the latest
            internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources'
          type: string
        kind:
          description: 'Kind is a string value representing the REST resource this
            object represents. Servers may infer this from the endpoint the client
            submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds'
          type: string
        metadata:
          type: object
        spec:
          properties:
            minReadySeconds:
              description: Minimum number of seconds for which a newly created machine
                should be ready. Defaults to 0 (machine will be considered available
                as soon as it is ready)
              format: int32
              type: integer
            paused:
              description: Indicates that the deployment is paused.
              type: boolean
            progressDeadlineSeconds:
              description: The maximum time in seconds for a deployment to make progress
                before it is considered to be failed. The deployment controller will
                continue to process failed deployments and a condition with a ProgressDeadlineExceeded
                reason will be surfaced in the deployment status. Note that progress
                will not be estimated during the time a deployment is paused. Defaults
                to 600s.
              format: int32
              type: integer
            replicas:
              description: Number of desired machines. Defaults to 1. This is a pointer
                to distinguish between explicit zero and not specified.
              format: int32
              type: integer
            revisionHistoryLimit:
              description: The number of old MachineSets to retain to allow rollback.
                This is a pointer to distinguish between explicit zero and not specified.
                Defaults to 1.
              format: int32
              type: integer
            selector:
              description: Label selector for machines. Existing MachineSets whose
                machines are selected by this will be the ones affected by this deployment.
                It must match the machine template's labels.
              type: object
            strategy:
              description: The deployment strategy to use to replace existing machines
                with new ones.
              properties:
                rollingUpdate:
                  description: Rolling update config params. Present only if MachineDeploymentStrategyType
                    = RollingUpdate.
                  properties:
                    maxSurge:
                      description: 'The maximum number of machines that can be scheduled
                        above the desired number of machines. Value can be an absolute
                        number (ex: 5) or a percentage of desired machines (ex: 10%).
                        This can not be 0 if MaxUnavailable is 0. Absolute number
                        is calculated from percentage by rounding up. Defaults to
                        1. Example: when this is set to 30%, the new MachineSet can
                        be scaled up immediately when the rolling update starts, such
                        that the total number of old and new machines do not exceed
                        130% of desired machines. Once old machines have been killed,
                        new MachineSet can be scaled up further, ensuring that total
                        number of machines running at any time during the update is
                        at most 130% of desired machines.'
                      oneOf:
                      - type: string
                      - type: integer
                    maxUnavailable:
                      description: 'The maximum number of machines that can be unavailable
                        during the update. Value can be an absolute number (ex: 5)
                        or a percentage of desired machines (ex: 10%). Absolute number
                        is calculated from percentage by rounding down. This can not
                        be 0 if MaxSurge is 0. Defaults to 0. Example: when this is
                        set to 30%, the old MachineSet can be scaled down to 70% of
                        desired machines immediately when the rolling update starts.
                        Once new machines are ready, old MachineSet can be scaled
                        down further, followed by scaling up the new MachineSet, ensuring
                        that the total number of machines available at all times during
                        the update is at least 70% of desired machines.'
                      oneOf:
                      - type: string
                      - type: integer
                  type: object
                type:
                  description: Type of deployment. Currently the only supported strategy
                    is "RollingUpdate". Default is RollingUpdate.
                  type: string
              type: object
            template:
              description: Template describes the machines that will be created.
              properties:
                metadata:
                  description: 'Standard object''s metadata. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata'
                  type: object
                spec:
                  description: 'Specification of the desired behavior of the machine.
                    More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#spec-and-status'
                  properties:
                    configSource:
                      description: ConfigSource is used to populate in the associated
                        Node for dynamic kubelet config. This field already exists
                        in Node, so any updates to it in the Machine spec will be
                        automatically copied to the linked NodeRef from the status.
                        The rest of dynamic kubelet config support should then work
                        as-is.
                      type: object
                    metadata:
                      description: ObjectMeta will autopopulate the Node created.
                        Use this to indicate what labels, annotations, name prefix,
                        etc., should be used when creating the Node.
                      type: object
                    providerID:
                      description: ProviderID is the identification ID of the machine
                        provided by the provider. This field must match the provider
                        ID as seen on the node object corresponding to this machine.
                        This field is required by higher level consumers of cluster-api.
                        Example use case is cluster autoscaler with cluster-api as
                        provider. Clean-up login in the autoscaler compares machines
                        v/s nodes to find out machines at provider which could not
                        get registered as Kubernetes nodes. With cluster-api as a
                        generic out-of-tree provider for autoscaler, this field is
                        required by autoscaler to be able to have a provider view
                        of the list of machines. Another list of nodes is queries
                        from the k8s apiserver and then comparison is done to find
                        out unregistered machines and are marked for delete. This
                        field will be set by the actuators and consumed by higher
                        level entities like autoscaler  who will be interfacing with
                        cluster-api as generic provider.
                      type: string
                    providerSpec:
                      description: ProviderSpec details Provider-specific configuration
                        to use during node creation.
                      properties:
                        value:
                          description: Value is an inlined, serialized representation
                            of the resource configuration. It is recommended that
                            providers maintain their own versioned API types that
                            should be serialized/deserialized from this field, akin
                            to component config.
                          type: object
                        valueFrom:
                          description: Source for the provider configuration. Cannot
                            be used if value is not empty.
                          properties:
                            machineClass:
                              description: The machine class from which the provider
                                config should be sourced.
                              properties:
                                provider:
                                  description: Provider is the name of the cloud-provider
                                    which MachineClass is intended for.
                                  type: string
                              type: object
                          type: object
                      type: object
                    taints:
                      description: Taints is the full, authoritative list of taints
                        to apply to the corresponding Node. This list will overwrite
                        any modifications made to the Node on an ongoing basis.
                      items:
                        type: object
                      type: array
                    versions:
                      description: Versions of key software to use. This field is
                        optional at cluster creation time, and omitting the field
                        indicates that the cluster installation tool should select
                        defaults for the user. These defaults may differ based on
                        the cluster installer, but the tool should populate the values
                        it uses when persisting Machine objects. A Machine spec missing
                        this field at runtime is invalid.
                      properties:
                        controlPlane:
                          description: ControlPlane is the semantic version of the
                            Kubernetes control plane to run. This should only be populated
                            when the machine is a control plane.
                          type: string
                        kubelet:
                          description: Kubelet is the semantic version of kubelet
                            to run
                          type: string
                      required:
                      - kubelet
                      type: object
                  required:
                  - providerSpec
                  type: object
              type: object
          required:
          - selector
          - template
          type: object
        status:
          properties:
            availableReplicas:
              description: Total number of available machines (ready for at least
                minReadySeconds) targeted by this deployment.
              format: int32
              type: integer
            observedGeneration:
              description: The generation observed by the deployment controller.
              format: int64
              type: integer
            readyReplicas:
              description: Total number of ready machines targeted by this deployment.
              format: int32
              type: integer
            replicas:
              description: Total number of non-terminated machines targeted by this
                deployment (their labels match the selector).
              format: int32
              type: integer
            unavailableReplicas:
              description: Total number of unavailable machines targeted by this deployment.
                This is the total number of machines that are still required for the
                deployment to have 100% available capacity. They may either be machines
                that are running but not yet available or machines that still have
                not been created.
              format: int32
              type: integer
            updatedReplicas:
              description: Total number of non-terminated machines targeted by this
                deployment that have the desired template spec.
              format: int32
              type: integer
          type: object
  version: v1alpha1
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []

---

### cluster_v1alpha1_machineset.yaml ###

apiVersion: apiextensions.k8s.io/v1beta1
kind: CustomResourceDefinition
metadata:
  creationTimestamp: null
  labels:
    controller-tools.k8s.io: "1.0"
  name: machinesets.cluster.k8s.io
spec:
  group: cluster.k8s.io
  names:
    kind: MachineSet
    plural: machinesets
  scope: Namespaced
  subresources:
    scale:
      labelSelectorPath: .status.labelSelector
      specReplicasPath: .spec.replicas
      statusReplicasPath: .status.replicas
    status: {}
  validation:
    openAPIV3Schema:
      properties:
        apiVersion:
          description: 'APIVersion defines the versioned schema of this representation
            of an object. Servers should convert recognized schemas to the latest
            internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#resources'
          type: string
        kind:
          description: 'Kind is a string value representing the REST resource this
            object represents. Servers may infer this from the endpoint the client
            submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds'
          type: string
        metadata:
          type: object
        spec:
          properties:
            minReadySeconds:
              description: MinReadySeconds is the minimum number of seconds for which
                a newly created machine should be ready. Defaults to 0 (machine will
                be considered available as soon as it is ready)
              format: int32
              type: integer
            replicas:
              description: Replicas is the number of desired replicas. This is a pointer
                to distinguish between explicit zero and unspecified. Defaults to
                1.
              format: int32
              type: integer
            selector:
              description: 'Selector is a label query over machines that should match
                the replica count. Label keys and values that must match in order
                to be controlled by this MachineSet. It must match the machine template''s
                labels. More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors'
              type: object
            template:
              description: Template is the object that describes the machine that
                will be created if insufficient replicas are detected.
              properties:
                metadata:
                  description: 'Standard object''s metadata. More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata'
                  type: object
                spec:
                  description: 'Specification of the desired behavior of the machine.
                    More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#spec-and-status'
                  properties:
                    configSource:
                      description: ConfigSource is used to populate in the associated
                        Node for dynamic kubelet config. This field already exists
                        in Node, so any updates to it in the Machine spec will be
                        automatically copied to the linked NodeRef from the status.
                        The rest of dynamic kubelet config support should then work
                        as-is.
                      type: object
                    metadata:
                      description: ObjectMeta will autopopulate the Node created.
                        Use this to indicate what labels, annotations, name prefix,
                        etc., should be used when creating the Node.
                      type: object
                    providerID:
                      description: ProviderID is the identification ID of the machine
                        provided by the provider. This field must match the provider
                        ID as seen on the node object corresponding to this machine.
                        This field is required by higher level consumers of cluster-api.
                        Example use case is cluster autoscaler with cluster-api as
                        provider. Clean-up login in the autoscaler compares machines
                        v/s nodes to find out machines at provider which could not
                        get registered as Kubernetes nodes. With cluster-api as a
                        generic out-of-tree provider for autoscaler, this field is
                        required by autoscaler to be able to have a provider view
                        of the list of machines. Another list of nodes is queries
                        from the k8s apiserver and then comparison is done to find
                        out unregistered machines and are marked for delete. This
                        field will be set by the actuators and consumed by higher
                        level entities like autoscaler  who will be interfacing with
                        cluster-api as generic provider.
                      type: string
                    providerSpec:
                      description: ProviderSpec details Provider-specific configuration
                        to use during node creation.
                      properties:
                        value:
                          description: Value is an inlined, serialized representation
                            of the resource configuration. It is recommended that
                            providers maintain their own versioned API types that
                            should be serialized/deserialized from this field, akin
                            to component config.
                          type: object
                        valueFrom:
                          description: Source for the provider configuration. Cannot
                            be used if value is not empty.
                          properties:
                            machineClass:
                              description: The machine class from which the provider
                                config should be sourced.
                              properties:
                                provider:
                                  description: Provider is the name of the cloud-provider
                                    which MachineClass is intended for.
                                  type: string
                              type: object
                          type: object
                      type: object
                    taints:
                      description: Taints is the full, authoritative list of taints
                        to apply to the corresponding Node. This list will overwrite
                        any modifications made to the Node on an ongoing basis.
                      items:
                        type: object
                      type: array
                    versions:
                      description: Versions of key software to use. This field is
                        optional at cluster creation time, and omitting the field
                        indicates that the cluster installation tool should select
                        defaults for the user. These defaults may differ based on
                        the cluster installer, but the tool should populate the values
                        it uses when persisting Machine objects. A Machine spec missing
                        this field at runtime is invalid.
                      properties:
                        controlPlane:
                          description: ControlPlane is the semantic version of the
                            Kubernetes control plane to run. This should only be populated
                            when the machine is a control plane.
                          type: string
                        kubelet:
                          description: Kubelet is the semantic version of kubelet
                            to run
                          type: string
                      required:
                      - kubelet
                      type: object
                  required:
                  - providerSpec
                  type: object
              type: object
          required:
          - selector
          type: object
        status:
          properties:
            availableReplicas:
              description: The number of available replicas (ready for at least minReadySeconds)
                for this MachineSet.
              format: int32
              type: integer
            errorMessage:
              type: string
            errorReason:
              description: In the event that there is a terminal problem reconciling
                the replicas, both ErrorReason and ErrorMessage will be set. ErrorReason
                will be populated with a succinct value suitable for machine interpretation,
                while ErrorMessage will contain a more verbose string suitable for
                logging and human consumption.  These fields should not be set for
                transitive errors that a controller faces that are expected to be
                fixed automatically over time (like service outages), but instead
                indicate that something is fundamentally wrong with the MachineTemplate's
                spec or the configuration of the machine controller, and that manual
                intervention is required. Examples of terminal errors would be invalid
                combinations of settings in the spec, values that are unsupported
                by the machine controller, or the responsible machine controller itself
                being critically misconfigured.  Any transient errors that occur during
                the reconciliation of Machines can be added as events to the MachineSet
                object and/or logged in the controller's output.
              type: string
            fullyLabeledReplicas:
              description: The number of replicas that have labels matching the labels
                of the machine template of the MachineSet.
              format: int32
              type: integer
            observedGeneration:
              description: ObservedGeneration reflects the generation of the most
                recently observed MachineSet.
              format: int64
              type: integer
            readyReplicas:
              description: The number of ready replicas for this MachineSet. A machine
                is considered ready when the node has been created and is "Ready".
              format: int32
              type: integer
            replicas:
              description: Replicas is the most recently observed number of replicas.
              format: int32
              type: integer
          required:
          - replicas
          type: object
  version: v1alpha1
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []

---

### rbac_role.yaml ###

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  creationTimestamp: null
  name: manager-role
rules:
- apiGroups:
  - cluster.k8s.io
  resources:
  - clusters
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - cluster.k8s.io
  resources:
  - machines
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - cluster.k8s.io
  resources:
  - machinedeployments
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - cluster.k8s.io
  resources:
  - machinesets
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - cluster.k8s.io
  resources:
  - machines
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - ""
  resources:
  - nodes
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete
- apiGroups:
  - cluster.k8s.io
  resources:
  - machines
  verbs:
  - get
  - list
  - watch
  - create
  - update
  - patch
  - delete

---

### rbac_role_binding.yaml ###

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  creationTimestamp: null
  name: manager-rolebinding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: manager-role
subjects:
- kind: ServiceAccount
  name: default
  namespace: system

---

### onecloud-manager-deployment.yaml ###
apiVersion: v1
kind: ServiceAccount
metadata:
  name: onecloud-clusterapi-manager
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
  name: onecloud-clusterapi-manager
  namespace: kube-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: onecloud-clusterapi-manager
  annotations:
     scheduler.alpha.kubernetes.io/critical-pod: ''
  name: onecloud-clusterapi-manager
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: onecloud-clusterapi-manager
  template:
    metadata:
      labels:
        k8s-app: onecloud-clusterapi-manager
    spec:
      hostNetwork: true
      serviceAccountName: onecloud-clusterapi-manager
      tolerations:
      - operator: Exists
        effect: NoSchedule
      - operator: Exists
        effect: NoExecute
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
      - name: manager
        image: {{.Image}}
        command:
        - /manager
        - -auth-url={{.YunionAuthURL}}
        - -username={{.YunionAdminUser}}
        - -password={{.YunionAdminPasswd}}
        - -project={{.YunionAdminProject}}
        volumeMounts:
        - mountPath: /etc/kubernetes
          name: kubernetes-config
      volumes:
      - hostPath:
          path: /etc/kubernetes
          type: Directory
        name: kubernetes-config
`
