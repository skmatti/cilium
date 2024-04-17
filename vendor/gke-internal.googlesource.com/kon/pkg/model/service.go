package model

type ServiceType string

type Service struct {
	Namespace string
	Name      string
	Type      ServiceType

	IP    string
	Ports []ServicePort
}

type ServicePort struct {
	Port     uint32
	Name     string
	Protocol string
	// The name of the CDS cluster for the port
	XDSCluster string
}
