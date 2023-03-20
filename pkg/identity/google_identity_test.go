package identity

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

func (s *IdentityTestSuite) TestMultiNICHostIdenities(c *C) {
	option.Config.EnableGoogleMultiNICHostFirewall = true
	defer func() {
		option.Config.EnableGoogleMultiNICHostFirewall = false
	}()

	err := InitMultiNICHostNumericIdentitySet(map[string]string{
		"135": "node-network1",
	})
	c.Assert(err, IsNil)

	c.Assert(IsMultiNICHostID(NumericIdentity(135)), Equals, true)
	c.Assert(IsMultiNICHostID(NumericIdentity(136)), Equals, false)

	lbls := labels.NewReservedMultiNICHostLabels("node-network1")
	lbls.MergeLabels(labels.LabelHost)
	id, ok := ReservedMultiNICHostIDForLabels(lbls)
	c.Assert(ok, Equals, true)
	c.Assert(id, Equals, NumericIdentity(135))

	net2Lbls := labels.NewReservedMultiNICHostLabels("node-network2")
	net2Lbls.MergeLabels(labels.LabelRemoteNode)
	id, ok = ReservedMultiNICHostIDForLabels(net2Lbls)
	c.Assert(ok, Equals, false)

	// Delete the reserved identity
	err = DeleteReservedIdentity(NumericIdentity(135))
	c.Assert(err, IsNil)

	c.Assert(IsMultiNICHostID(NumericIdentity(135)), Equals, false)
	_, ok = ReservedMultiNICHostIDForLabels(lbls)
	c.Assert(ok, Equals, false)
}
