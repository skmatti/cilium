package v1

const (
	ControllerName          = "persistent-ip-controller"
	GKEIPRouteFinalizer     = "networking.gke.io/gke-ipr-controller"
	NetworkEndpointGroupKey = "networking.gke.io/pip-neg"
	BackendServiceKey       = "networking.gke.io/pip-bs"
	ForwardingRuleKey       = "networking.gke.io/pip-fr"
	FirewallKey             = "networking.gke.io/pip-fw"
)

// GatewayClasses
type GatewayClass string

const (
	// ExternalManaged supports external IPs as persistent IPs.
	ExternalManaged GatewayClass = "gke-persistent-regional-external-managed"
	// InternalManaged supports GCP internal IPs as persistent IPs.
	InternalManaged GatewayClass = "gke-persistent-regional-internal-managed"
	// FastExternalManaged supports external IPs as persistent IPs with fast convergence.
	FastExternalManaged GatewayClass = "gke-persistent-fast-regional-external-managed"
	// FastInternalManaged supports internal IPs as persistent IPs with fast convergence.
	FastInternalManaged GatewayClass = "gke-persistent-fast-regional-internal-managed"
)

// IPRouteConditionType is the type for status conditions on
// a IPRoute. This type should be used with the
// IPRouteStatus.Conditions field.
type IPRouteConditionType string

const (
	// IPRouteAccepted is the condition type that holds
	// if the IPRoute object is validated
	IPRouteAccepted IPRouteConditionType = "Accepted"
	// IPRouteStatusReady is the condition type that holds
	// if the IPRoute programming including GCP and datapath is done.
	IPRouteStatusReady IPRouteConditionType = "Ready"
	// IPRouteDPV2Ready is the condition type that holds
	// if the datapath programming for IPRoute is complete.
	IPRouteDPV2Ready IPRouteConditionType = "DPV2Ready"
	// IPRouteDPV2Ready is the condition type that holds
	// if the GCP resource programming for IPRoute is complete.
	IPRouteGCPReady IPRouteConditionType = "IPRouteGCPReady"
)

// IPRouteAcceptedConditionReason defines the set of reasons for the status
// of an IPRoute Accepted condition.
type IPRouteAcceptedConditionReason string

const (
	// InvalidLabels indicates that the labels on GKEIPRoute are not parseable.
	InvalidLabels IPRouteAcceptedConditionReason = "InvalidLabels"
	// MissingParentRefs indicates that the parentRefs are missing in the GKEIPRoute spec.
	MissingParentRefs IPRouteAcceptedConditionReason = "MissingParentRefs"
	// GatewayNotFound indicates that the referenced gateway was not found.
	GatewayNotFound IPRouteAcceptedConditionReason = "GatewayNotFound"
	// GatewayNotAccepted indicates that the referenced gateway is not accepted yet.
	GatewayNotAccepted IPRouteAcceptedConditionReason = "GatewayNotAccepted"
	// Unattachable indicates that the GKEIPRoute cannot be attached to
	// the referenced gateway as per gateway's accepted addresses and
	// listener configuration.
	Unattachable IPRouteAcceptedConditionReason = "Unattachable"
	// InvalidAddresses indicates that the addresses in the spec is invalid.
	// e.g. bad format or do not belong to the referenced gateway
	InvalidAddresses IPRouteAcceptedConditionReason = "InvalidAddresses"
	// NetworkNotFound indicates that the network in the IPRoute spec does
	// does not exists.
	NetworkNotFound IPRouteAcceptedConditionReason = "NetworkNotFound"
	// NetworkNotReady indicates that the network in the IPRoute spec
	// is not ready yet.
	NetworkNotReady IPRouteAcceptedConditionReason = "NetworkNotReady"
	// Accepted indicates that the IPRoute passed all validations.
	Accepted IPRouteAcceptedConditionReason = "Accepted"
)

// IPRouteReadyConditionReason defines the set of reasons for the status
// of an IPRoute Ready condition.
type IPRouteReadyConditionReason string

const (
	// ProgrammingComplete indicates that the GCP and datapath components
	// of an IPRoute are programmed to handle traffic properly.
	ProgrammingComplete IPRouteReadyConditionReason = "ProgrammingComplete"
)

// IPRouteDPV2ReadyConditionReason defines the set of reasons for the status
// of an IPRouteDPV2Ready condition.
type IPRouteDPV2ReadyConditionReason string

const (
	// DPV2NotReady indicates that dataplane programming is in progress/failed.
	DPV2NotReady IPRouteDPV2ReadyConditionReason = "DPV2NotReady"
)

// IPRouteGCPReadyConditionReason defines the set of reasons for the status
// of an IPRouteGCPReady condition.
type IPRouteGCPReadyConditionReason string

const (
	// GCPNotReady indicates that GCP programming is in progress.
	GCPNotReady IPRouteGCPReadyConditionReason = "GCPNotReady"
	// GCPFailed indicates that GCP programming has failed.
	GCPFailed IPRouteGCPReadyConditionReason = "GCPFailed"
	// CleanupComplete indicates that GCP resources have been deleted.
	CleanupComplete IPRouteGCPReadyConditionReason = "CleanupComplete"
)

// CommonConditionReason represents reasons that could be common across all the conditions
type CommonConditionReason string

const (
	// NoPodsFound indicates that there are no matching pods.
	NoPodsFound CommonConditionReason = "NoPodsFound"
	// Mutated indicates that GKEIPRoute has been modified and
	// configuration is in progress.
	Mutated CommonConditionReason = "Mutated"
)

func SupportedClasses() map[GatewayClass]bool {
	return map[GatewayClass]bool{
		ExternalManaged:     true,
		InternalManaged:     true,
		FastExternalManaged: true,
		FastInternalManaged: true,
	}
}
