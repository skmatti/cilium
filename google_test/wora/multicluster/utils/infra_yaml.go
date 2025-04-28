package utils

import (
	"fmt"
	"net"
	"os"

	"sigs.k8s.io/yaml"
)

// GCEInstance represents a GCE instance in the infra yaml file.
type GCEInstance struct {
	ActualGCEIP  net.IP `json:"ActualGCEIP"`
	ExternalIP   net.IP `json:"ExternalIP"`
	InternalIP   net.IP `json:"InternalIP"`
	Name         string `json:"Name"`
	Project      string `json:"Project"`
	InstanceType string `json:"Type"`
	Zone         string `json:"Zone"`
}

// InfraInfo represents the resources information from infra yaml file.
type InfraInfo struct {
	Resources struct {
		Machines struct {
			ControlNodes      []GCEInstance `json:"ControlNodes"`
			WorkerNodes       []GCEInstance `json:"WorkerNodes"`
			Bootstrap         *GCEInstance  `json:"bootstrap"`
			ExtraMachines     []GCEInstance `json:"ExtraMachines"`
			LoadbalancerNodes []GCEInstance `json:"LoadbalancerNodes"`
		} `json:"Machines"`
	} `json:"Resources"`
}

// InfraInfoFromYaml reads the infra yaml file and returns the InfraInfo.
func InfraInfoFromYaml(infraYaml string) (*InfraInfo, error) {
	data, err := os.ReadFile(infraYaml)
	if err != nil {
		return nil, fmt.Errorf("read infra yaml: %v", err)
	}
	var info InfraInfo
	if err := yaml.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("unmarshal yaml: %v", err)
	}
	return &info, nil
}
