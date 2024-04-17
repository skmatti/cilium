// The file utils.go contains functions for stringifying.
package eventcache

import (
	"fmt"
)

func (hca resourcedEvent) String() string {
	if hca.sotw {
		return "report state of the world"
	}
	return fmt.Sprintf("%s %s", hca.resource.String(), hca.event.String())
}

func (r resource) String() string {
	switch r {
	case resourceUndefined:
		return "undefined"
	case resourceService:
		return "service"
	case resourcePort:
		return "port"
	case resourceEndpoint:
		return "endpoint"
	default:
		panic("Only 4 values are allowed for the `resource` type.")
	}
}

func (e apiEvent) String() string {
	switch e {
	case eventUpdate:
		return "update"
	case eventDelete:
		return "delete"
	default:
		panic("Only two values are allowed for the `event` type.")
	}
}

func (a action) String() string {
	switch a {
	case actionNoOp:
		return "noop"
	case actionAdd:
		return "add"
	case actionModify:
		return "update"
	case actionDelete:
		return "delete"
	default:
		panic("Only 4 values are allowed for the `action` type.")
	}
}

func (t hybridCacheMetricType) String() string {
	switch t {
	case skipped:
		return "skipped"
	case lost:
		return "lost"
	case delay:
		return "delay"
	default:
		return ""
	}
}
