package localnodeip

import (
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/components"
)

func TestCIDRMatchesLocalNode(t *testing.T) {
	// Temporarily modify os.Args[0] to simulate running as cilium-agent.
	// Th isbool
	originalArgs := os.Args
	defer func() {
		os.Args = originalArgs
	}()
	os.Args[0] = components.CiliumDaemonTestName
	tests := []struct {
		name   string
		nodeIP string
		cidr   string
		want   bool
	}{
		{
			name:   "empty",
			nodeIP: "",
			cidr:   "",
			want:   false,
		},
		{
			name:   "ip_empty",
			nodeIP: "",
			cidr:   "10.0.0.0/8",
			want:   false,
		},
		{
			name:   "cidr_empty",
			nodeIP: "10.0.0.1",
			cidr:   "",
			want:   false,
		},
		{
			name:   "outside",
			nodeIP: "11.0.0.1",
			cidr:   "10.0.0.0/8",
			want:   false,
		},
		{
			name:   "match",
			nodeIP: "10.0.0.1",
			cidr:   "10.0.0.0/8",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Not concurrent safe.
			setDeviceIP(tt.nodeIP)

			if got := CIDRMatchesLocalNode(tt.cidr); got != tt.want {
				t.Errorf("nodeIP CIDRMatchesLocalNode(%q) = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}
