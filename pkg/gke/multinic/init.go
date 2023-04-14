package multinic

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/gke/multinic/nic"
	k8s "github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/node"
	networkv1 "k8s.io/cloud-provider-gcp/crd/apis/network/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/vishvananda/netlink"
)

const (
	timeoutWaitForIP = 5 * time.Minute
)

// PopulateNICInfoAnnotation populates the IP/PCI/name mapping of each PCI device on the node
// in a node annotation and patches the node.
func PopulateNICInfoAnnotation(ctx context.Context, k8sClient *k8s.K8sClient) error {
	existingAnnotation, err := getNICInfoAnnotationFromNode()
	if err != nil {
		return fmt.Errorf("failed to get nic-info annotation from node: %v", err)
	}
	if existingAnnotation != nil {
		log.Infof("Skipping populating %v, annotation %v already exists", networkv1.NICInfoAnnotationKey, *existingAnnotation)
		return nil
	}

	// Enumerates all devices under /sys/class/net, ignoring 'lo' and non-PCI devices
	nics, err := nic.FindPCINICs()
	if err != nil {
		return err
	}
	numNICs := len(nics)
	if numNICs == 0 {
		return fmt.Errorf("no PCI NIC detected")
	}

	refs := make(networkv1.NICInfoAnnotation, numNICs)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeoutWaitForIP)
	defer cancel()

	errs, _ := errgroup.WithContext(ctx)
	for i, nic := range nics {
		devName := nic.Name
		log.Infof("Found NIC %v", devName)

		link, err := netlink.LinkByName(devName)
		if err != nil {
			return fmt.Errorf("failed to find link by name %v: %v", devName, err)
		}
		idx := i
		// Use errgroup to bail on first non-recoverable error and kill all goroutines in the group.
		errs.Go(func() error {
			ip, err := waitForIP(timeoutCtx, link, netlink.FAMILY_V4, backoff.Exponential{})
			if err != nil {
				return err
			}
			refs[idx] = networkv1.NICInfoRef{BirthIP: ip, PCIAddress: *nics[idx].PCIAddress, BirthName: devName}
			return nil
		})
	}
	err = errs.Wait()
	if err != nil {
		return err
	}

	patch, err := getPatchForNICInfoAnnotation(&refs)
	if err != nil {
		return fmt.Errorf("failed to get nic-info patch: %v", err)
	}
	if _, err := k8sClient.CoreV1().Nodes().Patch(ctx, nodeTypes.GetName(), k8sTypes.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("unable to apply patch for %v annotation: %v", networkv1.NICInfoAnnotationKey, err)
	}
	log.Infof("Successfully applied %v annotation: %v", networkv1.NICInfoAnnotationKey, refs)
	return nil
}

func waitForIP(ctx context.Context, link netlink.Link, family int, backoff backoff.Exponential) (string, error) {
	for {
		// This is only used in non-dualstack GKE where we would only have one v4 CIDR per node NIC.
		// TODO(cuiwl): to support dualstack, we need to populate the address that north-interface
		// will expose.
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return "", fmt.Errorf("failed to get IP address for device %v: %v", link.Attrs().Name, err)
		}

		if len(addrs) > 0 {
			// Per the GKE MN API, there will be one and only one internal IPv4 address for each NIC.
			return addrs[0].IPNet.IP.String(), nil
		}

		err = backoff.Wait(ctx)
		if err != nil {
			return "", fmt.Errorf("timeout waiting for IP address for device %v to become available: %v", link.Attrs().Name, err)
		}
	}
}

func getPatchForNICInfoAnnotation(refs *networkv1.NICInfoAnnotation) ([]byte, error) {
	val, err := json.Marshal(refs)
	if err != nil {
		return nil, err
	}
	annotation := map[string]string{networkv1.NICInfoAnnotationKey: string(val)}
	raw, err := json.Marshal(annotation)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw)), nil
}

func getNICInfoAnnotationFromNode() (*networkv1.NICInfoAnnotation, error) {
	annotation, exists := node.GetAnnotations()[networkv1.NICInfoAnnotationKey]
	if !exists {
		log.Infof("no %v annotation: %v", networkv1.NICInfoAnnotationKey, node.GetAnnotations())
		return nil, nil
	}
	result, err := networkv1.ParseNICInfoAnnotation(annotation)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
