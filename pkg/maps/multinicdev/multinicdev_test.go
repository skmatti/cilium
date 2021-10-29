//go:build !privileged_tests
// +build !privileged_tests

package multinicdev

import (
	"net"
	"testing"
)

func TestParseMAC(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		want       MAC
		shouldFail bool
	}{
		{
			name:  "valid mac",
			input: "12:34:56:78:90:ab",
			want:  MAC{0x12, 0x34, 0x56, 0x78, 0x90, 0xab},
		},
		{
			name:       "empty input",
			input:      "",
			shouldFail: true,
		},
		{
			name:       "invalid mac",
			input:      "invalid-mac",
			shouldFail: true,
		},
		{
			name:       "mac more than 6 bytes",
			input:      "12:34:56:78:90:ab:cd",
			shouldFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseMAC(tc.input)
			if err != nil {
				if !tc.shouldFail {
					t.Fatalf("ParseMAC(%s) return err %v but want nil", tc.input, err)
				}
				return
			}
			if tc.shouldFail {
				t.Fatalf("ParseMAC(%s) return nil but want err", tc.input)
			}
			if got != tc.want {
				t.Fatalf("ParseMAC(%s) return %q but want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestMACString(t *testing.T) {
	netMAC, err := net.ParseMAC("12:34:56:78:90:ab")
	if err != nil {
		t.Fatalf("net.ParseMAC() failed: %v", err)
	}
	mac, err := ParseMAC(netMAC.String())
	if err != nil {
		t.Fatalf("ParseMAC() failed: %v", err)
	}
	if got, want := mac.String(), netMAC.String(); got != want {
		t.Fatalf("mac.String() returns %q but want %q", got, want)
	}
}
