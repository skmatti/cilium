package v1

const (
	ControllerName = "persistent-ip-controller"
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
)

// IPRouteAcceptedConditionReason defines the set of reasons for the status
// of an IPRoute Accepted condition.
type IPRouteAcceptedConditionReason string

const (
	// GatewayNotFound indicates that the referenced gateway was not found.
	GatewayNotFound IPRouteAcceptedConditionReason = "GatewayNotFound"
	// InvalidAddresses indicates that the addresses in the spec is invalid.
	// e.g. bad format or do not belong to the referenced gateway
	InvalidAddresses IPRouteAcceptedConditionReason = "InvalidAddresses"
	// NetworkNotFound indicates that the network in the IPRoute spec does
	// does not exists.
	NetworkNotFound IPRouteAcceptedConditionReason = "NetworkNotFound"
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
	// GCPNotReady indicates that GCP programming is in progress/failed.
	GCPNotReady IPRouteReadyConditionReason = "GCPNotReady"
	// DPV2NotReady indicates that dataplane programming is in progress/failed.
	DPV2NotReady IPRouteReadyConditionReason = "DPV2NotReady"
	// Mutated indicates that IPRoute has been modified and
	// IPRoute reprogramming is in progress.
	Mutated IPRouteReadyConditionReason = "Mutated"
)

func SupportedClasses() map[GatewayClass]bool {
	return map[GatewayClass]bool{
		ExternalManaged:     true,
		InternalManaged:     true,
		FastExternalManaged: true,
		FastInternalManaged: true,
	}
}
