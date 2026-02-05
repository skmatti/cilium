package logging

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var FtLogger = logging.DefaultLogger.WithField(logfields.LogSubsys, "flow-trace")
