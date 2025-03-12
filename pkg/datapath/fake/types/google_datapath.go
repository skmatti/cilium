package types

import (
	"context"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

func (f *FakeLoader) ReloadParentDevDatapath(ctx context.Context, device string, ep datapath.Endpoint) error {
	return nil
}
