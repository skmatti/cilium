package localnodeip

import (
	"testing"
)

func TestCIDRMatchesLocalNode(t *testing.T) {
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
