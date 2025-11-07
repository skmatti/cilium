package google_traffictagmap

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type PacketTaggingKey struct {
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16
	DestinationPort uint16
	Protocol        v2alpha1.FlowTaggerProtocol
}

func (p *PacketTaggingKey) NetworkSourceIP() (net.IP, error) {
	sourceIP := p.SourceIP
	if sourceIP == "" {
		sourceIP = "0.0.0.0"
	}
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return net.IP{}, fmt.Errorf("invalid source IP address format: %s", sourceIP)
	}
	return ip, nil
}

func (p *PacketTaggingKey) NetworkDestinationIP() (net.IP, error) {
	destinationIP := p.DestinationIP
	if destinationIP == "" {
		destinationIP = "0.0.0.0"
	}
	ip := net.ParseIP(destinationIP)
	if ip == nil {
		return net.IP{}, fmt.Errorf("invalid destiniation IP address format: %s", destinationIP)
	}
	return ip, nil
}

type PacketTaggingValue struct {
	TraceID uint16
}
