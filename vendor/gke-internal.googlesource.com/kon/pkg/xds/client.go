package xds

import (
	"context"
	"strings"
	"sync"
	"time"

	corepb "github.com/cilium/proxy/go/envoy/config/core/v3"
	discoverypb "github.com/cilium/proxy/go/envoy/service/discovery/v3"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	bufferSize = 32
)

// Client represent an xDS client that streaming updates of xDS resources
type Client struct {
	logger *logrus.Entry
	// nodeProto uniquely identifies a xDS client
	nodeProto    *corepb.Node
	discoverycli discoverypb.AggregatedDiscoveryServiceClient

	errCh        chan error
	requestQueue chan *discoverypb.DiscoveryRequest
	// tracks keep the states of all types of the watched xDS resources
	tracks map[string]*track
}

// track watches a single resource.
// All the requests and responses in a track share a unique nonce.
type track struct {
	sync.RWMutex
	// Names of the resources been resources
	resources mapset.Set[string]
	nonce     string
	version   string
}

// NewClient returns a new xDS client.
func NewClient(conn *grpc.ClientConn, nodeProto *corepb.Node, logger *logrus.Entry) *Client {
	return &Client{
		logger:       logger,
		nodeProto:    nodeProto,
		discoverycli: discoverypb.NewAggregatedDiscoveryServiceClient(conn),
		requestQueue: make(chan *discoverypb.DiscoveryRequest, bufferSize),
		errCh:        make(chan error, bufferSize),
		tracks:       make(map[string]*track),
	}
}

// Watch informs the client to start watch on the resources of the given type.
// Returns true if the client will start to watch the given resources.
func (cli *Client) Watch(typeURL string, names []string) bool {
	// Only watch supported URLs
	if _, ok := cli.tracks[typeURL]; !ok {
		return false
	}

	track := cli.tracks[typeURL]
	track.Lock()
	defer track.Unlock()

	s := mapset.NewSet[string](names...)
	// Do not send new requests if there's no additional resources to track.
	// An empty watching names means watching all resources
	if s.Cardinality() != 0 && track.resources.Equal(s) {
		return false
	}
	track.resources = s
	cli.requestQueue <- &discoverypb.DiscoveryRequest{
		Node:          cli.nodeProto,
		TypeUrl:       typeURL,
		ResourceNames: s.Clone().ToSlice(),
		VersionInfo:   track.version,
		ResponseNonce: track.nonce,
	}
	return true
}

// Handler handles the updates of xDS resources.
type Handler interface {
	HandleResponse(*corepb.Locality, *discoverypb.DiscoveryResponse) error
}

// Run starts the client to watch xDS resources.
// The client waits for reconnectInterval before re-creating the stream.
func (cli *Client) Run(ctx context.Context, reconnectInterval time.Duration, h Handler) <-chan error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				cli.logger.Infof("xDS client stopped: context cancelled")
				return
			default:
			}
			// Cancel the context to ensure the stream is closed for sure.
			streamCtx, cancel := context.WithCancel(ctx)
			s, err := cli.discoverycli.StreamAggregatedResources(streamCtx, grpc.WaitForReady(true))
			if err != nil {
				cli.errCh <- err
				time.Sleep(reconnectInterval)
				cancel()
				continue
			}
			cli.logger.Infof("xDS stream estabilished. Watching for updates.")
			for _, r := range []string{LDS, RDS, CDS, EDS} {
				cli.tracks[r] = &track{
					resources: mapset.NewSet[string](),
				}
			}
			cli.Watch(LDS, []string{})
			cli.loop(ctx, s, h)
			time.Sleep(reconnectInterval)
			cancel()
		}
	}()
	return cli.errCh
}

func (cli *Client) loop(ctx context.Context, s discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient, h Handler) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Goroutine for handling requests
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case req := <-cli.requestQueue:
				if err := s.Send(req); err != nil {
					cli.errCh <- err
				}
			}
		}
	}()

	for {
		resp, err := s.Recv()
		if err != nil {
			if shouldResetStream(err) {
				cli.logger.Warningf("Reset xDS stream due to the following error: %v", err)
				return
			}
			cli.errCh <- err
			continue
		}
		typeURL := resp.TypeUrl
		t := cli.tracks[typeURL]
		if t == nil {
			cli.logger.Warningf("Received unexpected response with the type URL of %s", typeURL)
			continue
		}
		t.Lock()
		t.nonce = resp.Nonce
		req := &discoverypb.DiscoveryRequest{
			Node:          cli.nodeProto,
			TypeUrl:       typeURL,
			ResourceNames: t.resources.Clone().ToSlice(),
			ResponseNonce: resp.Nonce,
		}

		err = h.HandleResponse(cli.nodeProto.GetLocality(), resp)
		if err != nil {
			// In case of error, send an NACK to the server.
			// The version of an NACK request is set to the vesion of the previous response.
			req.VersionInfo = t.version
			t.Unlock()
			cli.requestQueue <- req
			continue
		}
		// ACK the response with a request with the same version as the response
		req.VersionInfo = resp.VersionInfo
		cli.requestQueue <- req
		// Update the track version and nonce only after an ACK

		t.version = resp.VersionInfo
		t.Unlock()
	}
}

func shouldResetStream(err error) bool {
	if err != nil && strings.Contains(err.Error(), "EOF") {
		return true
	}
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Aborted, codes.Unavailable, codes.Canceled:
		return true
	default:
		return false
	}
}
