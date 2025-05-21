package google_ctmap

import (
	"testing"
)

func TestHasEgressNatFlag(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{
			name:  "No flags set",
			flags: 0,
			want:  false,
		},
		{
			name:  "EgressNatFlag set",
			flags: EgressNatFlagMask,
			want:  true,
		},
		{
			name:  "ELBFlag set",
			flags: ElbFlagMask,
			want:  false,
		},
		{
			name:  "Both flags set",
			flags: EgressNatFlagMask | ElbFlagMask,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := GoogleCtMapEntry4{Flags: tt.flags}
			if got := entry.EgressNatEnabled(); got != tt.want {
				t.Errorf("EgressNatEnabled() with flags %04b = %t, want %t", tt.flags, got, tt.want)
			}
		})
	}
}

func TestHasElbFlag(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{
			name:  "No flags set",
			flags: 0,
			want:  false,
		},
		{
			name:  "ELBFlag set",
			flags: ElbFlagMask,
			want:  true,
		},
		{
			name:  "EgressNatFlag flag set",
			flags: EgressNatFlagMask,
			want:  false,
		},
		{
			name:  "Both flags set",
			flags: EgressNatFlagMask | ElbFlagMask,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := GoogleCtMapEntry4{Flags: tt.flags}
			if got := entry.ElbEnabled(); got != tt.want {
				t.Errorf("HasElbFlag() with flags %04b = %t, want %t", tt.flags, got, tt.want)
			}
		})
	}
}

func TestSetEgressNatFlag(t *testing.T) {
	tests := []struct {
		name       string
		initial    uint32
		set        bool
		wantFlags  uint32
		wantEgress bool
		wantElb    bool // To ensure other flags are untouched
	}{
		{
			name:       "Set from 0",
			initial:    0,
			set:        true,
			wantFlags:  EgressNatFlagMask,
			wantEgress: true,
			wantElb:    false,
		},
		{
			name:       "Set from EgressNat already set",
			initial:    EgressNatFlagMask,
			set:        true,
			wantFlags:  EgressNatFlagMask,
			wantEgress: true,
			wantElb:    false,
		},
		{
			name:       "Set from ELB set (should not affect ELB)",
			initial:    ElbFlagMask,
			set:        true,
			wantFlags:  EgressNatFlagMask | ElbFlagMask,
			wantEgress: true,
			wantElb:    true,
		},
		{
			name:       "Clear from EgressNat set",
			initial:    EgressNatFlagMask,
			set:        false,
			wantFlags:  0,
			wantEgress: false,
			wantElb:    false,
		},
		{
			name:       "Clear from 0",
			initial:    0,
			set:        false,
			wantFlags:  0,
			wantEgress: false,
			wantElb:    false,
		},
		{
			name:       "Clear from both set (should not affect ELB)",
			initial:    EgressNatFlagMask | ElbFlagMask,
			set:        false,
			wantFlags:  ElbFlagMask,
			wantEgress: false,
			wantElb:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := GoogleCtMapEntry4{Flags: tt.initial}
			entry.SetEgressNatFlag(tt.set)

			if entry.Flags != tt.wantFlags {
				t.Errorf("SetEgressNatFlag() changed flags from %04b to %04b, want %04b", tt.initial, entry.Flags, tt.wantFlags)
			}
			if entry.EgressNatEnabled() != tt.wantEgress {
				t.Errorf("HasEgressNatFlag() after SetEgressNatFlag() is %t, want %t", entry.EgressNatEnabled(), tt.wantEgress)
			}
			if entry.ElbEnabled() != tt.wantElb {
				t.Errorf("HasElbFlag() after SetEgressNatFlag() is %t, want %t (should be unaffected)", entry.ElbEnabled(), tt.wantElb)
			}
		})
	}
}

func TestSetElbFlag(t *testing.T) {
	tests := []struct {
		name       string
		initial    uint32
		set        bool
		wantFlags  uint32
		wantEgress bool // To ensure other flags are untouched
		wantElb    bool
	}{
		{
			name:       "Set from 0",
			initial:    0,
			set:        true,
			wantFlags:  ElbFlagMask,
			wantEgress: false,
			wantElb:    true,
		},
		{
			name:       "Set from ELB already set",
			initial:    ElbFlagMask,
			set:        true,
			wantFlags:  ElbFlagMask,
			wantEgress: false,
			wantElb:    true,
		},
		{
			name:       "Set from EgressNat set (should not affect EgressNat)",
			initial:    EgressNatFlagMask,
			set:        true,
			wantFlags:  EgressNatFlagMask | ElbFlagMask,
			wantEgress: true,
			wantElb:    true,
		},
		{
			name:       "Clear from ELB set",
			initial:    ElbFlagMask,
			set:        false,
			wantFlags:  0,
			wantEgress: false,
			wantElb:    false,
		},
		{
			name:       "Clear from 0",
			initial:    0,
			set:        false,
			wantFlags:  0,
			wantEgress: false,
			wantElb:    false,
		},
		{
			name:       "Clear from both set (should not affect EgressNat)",
			initial:    EgressNatFlagMask | ElbFlagMask,
			set:        false,
			wantFlags:  EgressNatFlagMask,
			wantEgress: true,
			wantElb:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := GoogleCtMapEntry4{Flags: tt.initial}
			entry.SetElbFlag(tt.set)

			if entry.Flags != tt.wantFlags {
				t.Errorf("SetElbFlag() changed flags from %04b to %04b, want %04b", tt.initial, entry.Flags, tt.wantFlags)
			}
			if entry.ElbEnabled() != tt.wantElb {
				t.Errorf("HasElbFlag() after SetElbFlag() is %t, want %t", entry.ElbEnabled(), tt.wantElb)
			}
			if entry.EgressNatEnabled() != tt.wantEgress {
				t.Errorf("HasEgressNatFlag() after SetElbFlag() is %t, want %t (should be unaffected)", entry.EgressNatEnabled(), tt.wantEgress)
			}
		})
	}
}
