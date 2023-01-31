package v1

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	MaxServicePathId = (1 << 24) - 1

	SvcSteeringPort     = 7081
	SvcSteeringPortName = "service-steering"

	ManagedByKey   = "networking.gke.io/managed-by"
	ControllerName = "service-steering-controller.gke.io"
)

// Generate service name from the SFC UUID and the service function name.
// E.g. "proxy" -> "sf-proxy-40e89c70"
func ServiceName(sfName string, sfcUUID types.UID) string {
	prefix := "sf-"
	// use last 8 characters of SFC UUID as the suffix
	suffix := fmt.Sprintf("-%s", sfcUUID[len(sfcUUID)-8:])
	maxNameLen := validation.DNS1035LabelMaxLength - len(prefix) - len(suffix)
	return prefix + truncate(sfName, maxNameLen) + suffix
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[0:length]
}
