package identity

import (
	"testing"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/stretchr/testify/require"
)

func TestMultiNICHostIdenities(t *testing.T) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()

	nid := NumericIdentity(135)
	err := InitMultiNICHostNumericIdentitySet(map[string]string{
		nid.String(): "node-network1",
	})
	require.NoError(t, err)
	defer DeleteReservedIdentity(nid)

	require.Equal(t, true, IsMultiNICHostID(nid))
	require.Equal(t, false, IsMultiNICHostID(NumericIdentity(136)))

	lbls := labels.NewReservedMultiNICHostLabels("node-network1")
	lbls.MergeLabels(labels.LabelHost)
	id, ok := ReservedMultiNICHostIDForLabels(lbls)
	require.Equal(t, true, ok)
	require.Equal(t, NumericIdentity(135), id)

	net2Lbls := labels.NewReservedMultiNICHostLabels("node-network2")
	net2Lbls.MergeLabels(labels.LabelRemoteNode)
	id, ok = ReservedMultiNICHostIDForLabels(net2Lbls)
	require.Equal(t, false, ok)

	// Delete the reserved identity
	err = DeleteReservedIdentity(NumericIdentity(135))
	require.NoError(t, err)

	require.Equal(t, false, IsMultiNICHostID(NumericIdentity(135)))
	_, ok = ReservedMultiNICHostIDForLabels(lbls)
	require.Equal(t, false, ok)
}
