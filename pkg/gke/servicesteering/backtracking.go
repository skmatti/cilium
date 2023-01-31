package servicesteering

import (
	"net"
	"reflect"
	"sort"

	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/u8proto"
)

type protoCoverage struct {
	protos map[u8proto.U8proto]portCoverage
}

type portCoverage struct {
	ports map[uint16]struct{}
}

// Adds fallback entries to the provided selection map.
func addFallbackEntries(selectors map[sfc.SelectKey]sfc.PathKey) {
	egressFallbackEntries := fallbackEntries(selectors, true)
	ingressFallbackEntries := fallbackEntries(selectors, false)
	for k, v := range egressFallbackEntries {
		selectors[k] = v
	}
	for k, v := range ingressFallbackEntries {
		selectors[k] = v
	}
}

// Returns the fallback entries for the selection map by doing ahead-of-time backtracking.
func fallbackEntries(selectors map[sfc.SelectKey]sfc.PathKey, egress bool) map[sfc.SelectKey]sfc.PathKey {
	sortedKeys := []sfc.SelectKey{}
	for selector := range selectors {
		if selector.IsEgress() == egress {
			sortedKeys = append(sortedKeys, selector)
		}
	}
	// Sort selectors by prefix length in descending order (/32, /24, ... /0).
	// This gives priority to more-specific prefixes when creating fallback entries.
	sort.Slice(sortedKeys, func(i, j int) bool {
		return prefixLen(sortedKeys[i].GetCIDR()) > prefixLen(sortedKeys[j].GetCIDR())
	})

	fallbackEntries := make(map[sfc.SelectKey]sfc.PathKey)
	// For each selector, try to find selectors with wider CIDRs that cover more protocols/ports.
	for _, selector := range sortedKeys {
		cidr := selector.GetCIDR()
		cov := protoCoverage{}
		cov.add(selector.Protocol, selector.Port)
		for _, widerSelector := range sortedKeys {
			widerCIDR := widerSelector.GetCIDR()
			if prefixLen(widerCIDR) > prefixLen(cidr) || !widerCIDR.Contains(cidr.IP) {
				// Wider CIDR doesn't contain inner CIDR, so this isn't a valid backtracking target
				// and doesn't require fallback entries.
				continue
			}
			if cov.add(widerSelector.Protocol, widerSelector.Port) {
				// Backtracking target expanded the protocol/port coverage, so add a fallback
				// entry (if the CIDR is different).
				if reflect.DeepEqual(cidr, widerCIDR) {
					continue
				}
				fallbackSelector := selector.DeepCopy()
				fallbackSelector.Protocol = widerSelector.Protocol
				fallbackSelector.Port = widerSelector.Port
				fallbackEntries[*fallbackSelector] = selectors[widerSelector]
			}
		}
	}
	return fallbackEntries
}

func prefixLen(cidr *net.IPNet) int {
	ones, _ := cidr.Mask.Size()
	return ones
}

// Add protocol+port to the protocol coverage, returning true if the coverage was expanded.
func (c *protoCoverage) add(proto uint8, portNumber uint16) bool {
	if c.protos == nil {
		c.protos = make(map[u8proto.U8proto]portCoverage)
	}
	pc, ok := c.protos[u8proto.U8proto(proto)]
	if !ok {
		pc = portCoverage{ports: make(map[uint16]struct{})}
		c.protos[u8proto.U8proto(proto)] = pc
	}
	return pc.add(portNumber)
}

// Add port to set of covered ports, returning true if the coverage was expanded.
func (c *portCoverage) add(port uint16) bool {
	if _, ok := c.ports[0]; ok {
		// all ports are covered
		return false
	}
	if _, ok := c.ports[port]; ok {
		// port is already covered
		return false
	}
	c.ports[port] = exists
	return true
}
