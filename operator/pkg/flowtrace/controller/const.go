package controller

import pkgtime "github.com/cilium/cilium/pkg/time"

const (
	controllerName      = "flowtrace-controller"
	informerSyncPeriod  = 5 * pkgtime.Minute
	storeSyncPollPeriod = 100 * pkgtime.Millisecond
	loggerFieldKey      = "FlowTrace"
)
