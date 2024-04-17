package model

type EndpointSubset struct {
	// The name of the CDS cluster
	XDSCluster string
	Endpoints  []Endpoint
}

type Endpoint struct {
	Ready   bool
	Address Address
}

type Address struct {
	IP   string
	Zone string
	Port uint32
}
