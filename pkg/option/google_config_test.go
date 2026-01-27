package option

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGoogleConfigFlags(t *testing.T) {
	// Verify the constant value matches expectations
	assert.Equal(t, "xdp-mode", XDPMode)

	// Verify viper binding works as expected
	vp := viper.New()
	vp.Set(XDPMode, "native")

	c := &DaemonConfig{}
	c.Populate(vp)

	assert.Equal(t, "native", c.XDPMode)
}
