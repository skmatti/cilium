package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	l4gatewayv1 "gke-internal.googlesource.com/anthos-networking/apis/v2/l4-gateway/v1"
	klog "gke-internal.googlesource.com/syllogi/sanitized-klog/third_party/klogv2"
)

func computeNamespace(name string) string {
	if name == "" {
		return corev1.NamespaceDefault
	}
	return name
}

func gatewayClassObject(args GatewayClassArgs) *gatewayv1.GatewayClass {
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: args.Name,
		},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(args.ControllerName),
		},
	}
	return gc
}

func routeObject(args RouteArgs) *l4gatewayv1.GKEL4Route {
	return &l4gatewayv1.GKEL4Route{
		ObjectMeta: metav1.ObjectMeta{Name: args.Name, Namespace: computeNamespace(args.Namespace)},
		Spec: l4gatewayv1.GKEL4RouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name: gatewayv1.ObjectName(args.Gateway),
					},
				},
			},
			Rules: []l4gatewayv1.GKEL4RouteRule{
				{
					Name: ptr.To(gatewayv1.SectionName(args.RuleName)),
					BackendRefs: []gatewayv1.BackendRef{
						{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name:  gatewayv1.ObjectName(args.EndpointSelector),
								Port:  ptr.To(gatewayv1.PortNumber(args.Port)),
								Group: ptr.To(gatewayv1.Group("networking.gke.io")),
								Kind:  ptr.To(gatewayv1.Kind("GKEEndpointSelector")),
							},
						},
					},
				},
			},
		},
	}
}

func gatewayObject(args GatewayArgs) *gatewayv1.Gateway {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.Name,
			Namespace: computeNamespace(args.Namespace),
			Annotations: map[string]string{
				networkv1.NetworkAnnotationKey: args.Network,
			},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(args.GatewayClass),
			Listeners: []gatewayv1.Listener{
				{
					Name:     gatewayv1.SectionName(args.Listener),
					Protocol: gatewayv1.TCPProtocolType,
					Port:     gatewayv1.PortNumber(args.Port),
				},
			},
		},
	}

	if args.IPAddress != "" {
		addressType := gatewayv1.IPAddressType
		gw.Spec.Addresses = []gatewayv1.GatewayAddress{
			{
				Type:  &addressType,
				Value: args.IPAddress,
			},
		}
	}

	return gw
}

func endpointSelectorObject(args EndpointSelectorArgs) *l4gatewayv1.GKEEndpointSelector {
	return &l4gatewayv1.GKEEndpointSelector{
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.Name,
			Namespace: computeNamespace(args.Namespace),
		},
		Spec: l4gatewayv1.GKEEndpointSelectorSpec{
			Selector: metav1.LabelSelector{
				MatchLabels: args.Selector,
			},
			Network: args.Network,
		},
	}
}

func gatewayCIDRObject(args GatewayCIDRArgs) *l4gatewayv1.GKEGatewayCIDR {
	return &l4gatewayv1.GKEGatewayCIDR{
		ObjectMeta: metav1.ObjectMeta{
			Name:      args.Name,
			Namespace: computeNamespace(args.Namespace),
		},
		Spec: l4gatewayv1.GKEGatewayCIDRSpec{
			Network: args.Network,
			IP4CIDR: args.CIDR,
		},
	}
}
func createObject(ctx context.Context, cl k8sclient.Client, obj k8sclient.Object) error {
	f := func() error {
		if err := cl.Create(ctx, obj); err != nil {
			if apierrors.IsAlreadyExists(err) {
				klog.Infof("Object already exists.")
				return nil
			}
			return fmt.Errorf("failed to create object: %v", err)
		}
		return nil
	}

	if err := backoff.Retry(f, backoff.WithMaxRetries(backoff.NewConstantBackOff(defaultConstantBackOffTime), maxRetries)); err != nil {
		klog.Errorf("err creating object %s after %q retries: %v", obj.GetName(), maxRetries, err)
		return err
	}

	klog.Infof("object %s created successfully", obj.GetName())
	return nil
}

type GatewayClassArgs struct {
	Name           string
	ControllerName string
}

func CreateGatewayClass(ctx context.Context, cl k8sclient.Client, args GatewayClassArgs) error {
	gc := gatewayClassObject(args)
	return createObject(ctx, cl, gc)
}

type RouteArgs struct {
	Namespace        string
	Name             string
	RuleName         string
	Gateway          string
	EndpointSelector string
	Port             int32
}

func CreateRoute(ctx context.Context, cl k8sclient.Client, args RouteArgs) error {
	route := routeObject(args)
	if err := createObject(ctx, cl, route); err != nil {
		return err
	}
	return nil
}

type GatewayArgs struct {
	Namespace    string
	Name         string
	Network      string
	GatewayClass string
	Listener     string
	Port         int32
	IPAddress    string
}

func CreateGateway(ctx context.Context, cl k8sclient.Client, args GatewayArgs) error {
	gw := gatewayObject(args)
	if err := createObject(ctx, cl, gw); err != nil {
		return err
	}
	return nil
}

type EndpointSelectorArgs struct {
	Namespace string
	Name      string
	Network   string
	Selector  map[string]string
}

func CreateEndpointSelector(ctx context.Context, cl k8sclient.Client, args EndpointSelectorArgs) error {
	eps := endpointSelectorObject(args)
	if err := createObject(ctx, cl, eps); err != nil {
		return err
	}
	return nil
}

type GatewayCIDRArgs struct {
	Namespace string
	Name      string
	Network   string
	CIDR      string
}

func CreateGatewayCIDR(ctx context.Context, cl k8sclient.Client, args GatewayCIDRArgs) error {
	gwcidr := gatewayCIDRObject(args)
	if err := createObject(ctx, cl, gwcidr); err != nil {
		return err
	}
	return nil
}

func listEndpointSlices(ctx context.Context, cl k8sclient.Client, selector map[string]string) ([]discoveryv1.EndpointSlice, error) {
	labelSelector := &metav1.LabelSelector{
		MatchLabels: selector,
	}

	// Convert it to a labels.Selector which is often used by clients
	s, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to convert label selector: %w", err)
	}

	var eps discoveryv1.EndpointSliceList
	f := func() error {
		if err := cl.List(ctx, &eps, client.MatchingLabelsSelector{Selector: s}); err != nil {
			return fmt.Errorf("failed to list endpoint slices: %w", err)
		}
		return nil
	}
	if err := backoff.Retry(f, backoff.WithMaxRetries(backoff.NewConstantBackOff(defaultConstantBackOffTime), maxRetries)); err != nil {
		klog.Errorf("Failed to list endpoint slices with selector %v after %d retries: %v", selector, maxRetries, err)
		return nil, err
	}

	return eps.Items, nil
}

func EndpointSlicesForGateway(ctx context.Context, cl k8sclient.Client, name string) ([]discoveryv1.EndpointSlice, error) {
	selector := map[string]string{
		l4gatewayv1.GatewayNameKey: name,
	}
	return listEndpointSlices(ctx, cl, selector)
}

func EndpointSlicesForRoute(ctx context.Context, cl k8sclient.Client, name string) ([]discoveryv1.EndpointSlice, error) {
	selector := map[string]string{
		l4gatewayv1.GKEL4RouteNameKey: name,
	}
	return listEndpointSlices(ctx, cl, selector)
}

func isManagedGateway(ctx context.Context, cl k8sclient.Client, gw *gatewayv1.Gateway) bool {
	gc := &gatewayv1.GatewayClass{}
	gcKey := types.NamespacedName{Namespace: metav1.NamespaceDefault, Name: string(gw.Spec.GatewayClassName)}
	if err := cl.Get(ctx, gcKey, gc); err != nil {
		return false
	}

	return gc.Spec.ControllerName == l4gatewayv1.ClusterIPController
}

func CleanupL4Resources(ctx context.Context, cl k8sclient.Client, namespace string) error {
	cont, _ := context.WithTimeout(ctx, time.Minute)

	var gws gatewayv1.GatewayList
	if err := cl.List(cont, &gws); err != nil {
		klog.Errorf("failed to list gateways: %v", err)
		return err
	}

	for _, gw := range gws.Items {
		if !isManagedGateway(cont, cl, &gw) {
			continue
		}
		klog.Infof("deleting gateway: %s", gw.Name)
		if err := cl.Delete(cont, &gw); err != nil {
			if !apierrors.IsNotFound(err) {
				klog.Errorf("failed to delete gateway: %v", err)
				return err
			}
		}
	}

	if err := cl.DeleteAllOf(cont, &l4gatewayv1.GKEL4Route{}, client.InNamespace(namespace)); err != nil {
		klog.Errorf("failed to delete routes: %v", err)
		return err
	}

	if err := cl.DeleteAllOf(cont, &l4gatewayv1.GKEEndpointSelector{}, client.InNamespace(namespace)); err != nil {
		klog.Errorf("failed to delete endpoint selectors: %v", err)
		return err
	}

	if err := cl.DeleteAllOf(cont, &l4gatewayv1.GKEGatewayCIDR{}); err != nil {
		klog.Errorf("failed to delete endpoint selectors: %v", err)
		return err
	}

	return nil
}

func CleanupGatewayClass(ctx context.Context, cl k8sclient.Client, name string) error {
	gc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	if err := cl.Delete(ctx, gc); err != nil {
		if apierrors.IsNotFound(err) {
			klog.Infof("GatewayClass %s not found, assumed already deleted.", name)
			return nil
		}
		return fmt.Errorf("failed to delete GatewayClass %s: %w", name, err)
	}

	klog.Infof("GatewayClass %s deleted successfully.", name)
	return nil
}
