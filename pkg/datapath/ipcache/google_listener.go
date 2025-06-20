package ipcache

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/sirupsen/logrus"
)

func resolveTunnelEndpointIP(k8sMeta *ipcache.K8sMetadata) net.IP {
	if k8sMeta != nil && k8sMeta.ParentInterfaceIP != "" {
		tunnelIP := net.ParseIP(k8sMeta.ParentInterfaceIP).To4()
		if tunnelIP == nil {
			err := fmt.Errorf("invalid IP address: %s", k8sMeta.ParentInterfaceIP)
			log.WithError(err).WithFields(logrus.Fields{
				"ParentInterfaceIP": k8sMeta.ParentInterfaceIP,
			}).Warning("falling back to node IP")
			return nil
		}
		return tunnelIP
	}
	return nil
}
