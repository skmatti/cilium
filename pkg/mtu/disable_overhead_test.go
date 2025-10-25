package mtu

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDisableOverhead(t *testing.T) {
	baseConf := func() Configuration {
		return Configuration{
			standardMTU:    1500,
			tunnelMTU:      1450,
			preEncryptMTU:  1500,
			postEncryptMTU: 1450,
		}
	}

	t.Run("disableOverhead() - Disables Overhead", func(t *testing.T) {
		c := baseConf()
		c.disableOverhead(c.standardMTU)

		require.Equal(t, 1500, c.tunnelMTU)
		require.Equal(t, 1550, c.preEncryptMTU)
		require.Equal(t, 1500, c.postEncryptMTU)
	})

	t.Run("disableOverhead() with Encryption enabled", func(t *testing.T) {
		c := Configuration{
			standardMTU:    1500,
			tunnelMTU:      1373,
			preEncryptMTU:  1423,
			postEncryptMTU: 1450,
		}

		c.disableOverhead(c.standardMTU)

		require.Equal(t, 1500, c.tunnelMTU)
		require.Equal(t, 1550, c.preEncryptMTU)
		require.Equal(t, 1577, c.postEncryptMTU)
	})

	t.Run("disableOverhead() - Large MTU", func(t *testing.T) {
		c := Configuration{
			standardMTU:    9000,
			tunnelMTU:      8950,
			preEncryptMTU:  9000,
			postEncryptMTU: 8950,
		}

		c.disableOverhead(c.standardMTU)

		require.Equal(t, 9000, c.tunnelMTU)
		require.Equal(t, 9050, c.preEncryptMTU)
	})

	t.Run("disableOverhead() - Ignoring if no manual MTU is configured", func(t *testing.T) {
		c := baseConf()
		originalC := c
		c.disableOverhead(0)

		require.Equal(t, originalC, c)
	})
}
