// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"reflect"
	"sort"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
)

// FlowLogExporter exports hubble events to configured target file.
type FlowLogExporter interface {
	observeroption.OnDecodedEvent
	// Stop stops this exporter instance from further events processing.
	Stop() error
}

type FlowFilters []*flowpb.FlowFilter
type FieldMask []string

type flowLogConfig struct {
	Name           string      `yaml:"name"`
	FilePath       string      `yaml:"filePath"`
	FieldMask      FieldMask   `yaml:"fieldMask"`
	IncludeFilters FlowFilters `yaml:"includeFilters"`
	ExcludeFilters FlowFilters `yaml:"excludeFilters"`
	End            *time.Time  `yaml:"end"`
}

func (f *flowLogConfig) equals(other *flowLogConfig) bool {
	if f.FilePath != other.FilePath {
		return false
	}

	if !f.FieldMask.equals(other.FieldMask) {
		return false
	}

	if !f.IncludeFilters.equals(other.IncludeFilters) {
		return false
	}

	if !f.ExcludeFilters.equals(other.ExcludeFilters) {
		return false
	}

	if f.End == nil && other.End != nil ||
		f.End != nil && other.End == nil ||
		f.End != nil && other.End != nil && !f.End.Equal(*other.End) {
		return false
	}

	return true
}

func (f *FlowFilters) equals(other FlowFilters) bool {
	aFiltersSet, bFiltersSet := make(map[string]bool), make(map[string]bool)

	for _, filter := range *f {
		aFiltersSet[filter.String()] = true
	}
	for _, filter := range other {
		bFiltersSet[filter.String()] = true
	}
	return reflect.DeepEqual(aFiltersSet, bFiltersSet)
}

func (f *FieldMask) equals(other FieldMask) bool {
	sort.Strings(*f)
	sort.Strings(other)
	return reflect.DeepEqual(*f, other)
}

type dynamicExportersConfig struct {
	FlowLogs []*flowLogConfig `yaml:"flowlogs"`
}
