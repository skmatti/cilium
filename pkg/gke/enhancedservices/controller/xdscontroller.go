package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	"github.com/sirupsen/logrus"
	"gke-internal.googlesource.com/kon/pkg/model"
	"gke-internal.googlesource.com/kon/pkg/xds"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/google"
	"google.golang.org/grpc/credentials/oauth"
)

const (
	tdEndpoint = "dns:///trafficdirector.googleapis.com:443"
	// Retry interval for reconnect over connection failure
	reconnectInterval = 12 * time.Second
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "gke-xds-controller")
)

// XDSController for Traffic Director xDS.
type XDSController struct {
	xDSNode *corepb.Node
	conn    *grpc.ClientConn
}

// NewController returns a new controller for Traffic Director xDS.
func NewXDSController(mesh string) (*XDSController, error) {
	projectNumber, err := metadata.NumericProjectID()
	if err != nil {
		return nil, fmt.Errorf("failed to get the project number: %v", err)
	}
	zone, err := metadata.Zone()
	if err != nil {
		return nil, fmt.Errorf("failed to get the zone of the VM: %v", err)
	}
	nodeName := os.Getenv("K8S_NODE_NAME")
	xDSNode := &corepb.Node{
		Id:            fmt.Sprintf("projects/%s/networks/mesh:%s/nodes/%s", projectNumber, mesh, nodeName),
		UserAgentName: "",
		Locality: &corepb.Locality{
			Zone: zone,
		},
	}
	c := &XDSController{
		xDSNode: xDSNode,
	}
	return c, nil
}

func (c *XDSController) Start(ctx context.Context) error {
	log.Info("Starting GKE xDS controller")
	perRPCCreds, err := oauth.NewApplicationDefault(ctx)
	if err != nil {
		return fmt.Errorf("failed to get the OAuth credentials: %v", err)
	}
	creds := google.NewDefaultCredentialsWithOptions(google.DefaultCredentialsOptions{PerRPCCreds: perRPCCreds})
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds.TransportCredentials()),
		grpc.WithPerRPCCredentials(creds.PerRPCCredentials()),
	}
	conn, err := grpc.Dial(tdEndpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to Traffic Director: %v", err)
	}
	c.conn = conn

	cli := xds.NewClient(conn, c.xDSNode, logrus.NewEntry(log.Logger))
	h := &handler{
		cache:     k8s.HybridCache,
		swg:       lock.NewStoppableWaitGroup(),
		watch:     cli.Watch,
		services:  make(map[string]*model.Service),
		endpoints: make(map[string]*endpointSubsetWithID),
	}
	errCh := cli.Run(ctx, reconnectInterval, h)
	go func() {
		for err := range errCh {
			log.Warningf("Error received from the xDS client: %v", err)
		}
	}()
	return nil
}

func (c *XDSController) Stop() {
	if c.conn != nil {
		c.conn.Close()
	}
	log.Info("Shutting down GKE xDS controller")
}
