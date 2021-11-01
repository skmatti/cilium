//go:build !privileged_tests
// +build !privileged_tests

package labels

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMergeMultiNICLabels(t *testing.T) {
	testcases := []struct {
		desc           string
		to, from, want Labels
	}{
		{
			desc: "no multinic labels",
			to: Labels{
				"key1": NewLabel("key1", "value1", "source1"),
				"key2": NewLabel("key2", "value2", "source2"),
			},
			from: Labels{
				"key1": NewLabel("key1", "value3", "source3"),
			},
			want: Labels{
				"key1": NewLabel("key1", "value1", "source1"),
				"key2": NewLabel("key2", "value2", "source2"),
			},
		},
		{
			desc: "merge multinic labels",
			to: Labels{
				"key1": NewLabel("key1", "value1", "source1"),
				"key2": NewLabel("key2", "value2", "source2"),
			},
			from: Labels{
				multinicInterface: NewLabel(multinicInterface, "value3", "source4"),
				multinicNetwork:   NewLabel(multinicNetwork, "value3", "source4"),
			},
			want: Labels{
				"key1":            NewLabel("key1", "value1", "source1"),
				"key2":            NewLabel("key2", "value2", "source2"),
				multinicInterface: NewLabel(multinicInterface, "value3", "source4"),
				multinicNetwork:   NewLabel(multinicNetwork, "value3", "source4"),
			},
		},
		{
			desc: "merge multinic labels with overwriting",
			to: Labels{
				"key1":            NewLabel("key1", "value1", "source1"),
				multinicInterface: NewLabel(multinicInterface, "value2", "source2"),
			},
			from: Labels{
				multinicInterface: NewLabel(multinicInterface, "value3", "source4"),
				multinicNetwork:   NewLabel(multinicNetwork, "value3", "source4"),
			},
			want: Labels{
				"key1":            NewLabel("key1", "value1", "source1"),
				multinicInterface: NewLabel(multinicInterface, "value3", "source4"),
				multinicNetwork:   NewLabel(multinicNetwork, "value3", "source4"),
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			tc.to.MergeMultiNICLabels(tc.from)
			if diff := cmp.Diff(tc.to, tc.want); diff != "" {
				t.Fatalf("MergeMultiNICLabels() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}
