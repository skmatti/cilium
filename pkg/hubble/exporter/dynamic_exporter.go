// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
	"github.com/cilium/cilium/pkg/lock"
)

type dynamicExporter struct {
	FlowLogExporter
	logger           logrus.FieldLogger
	watcher          *configWatcher
	managedExporters map[string]*managedExporter
	maxFileSizeMB    int
	maxBackups       int
	mutex            lock.RWMutex
}

// OnDecodedEvent distributes events across all managed exporters.
func (d *dynamicExporter) OnDecodedEvent(ctx context.Context, event *v1.Event) (bool, error) {
	select {
	case <-ctx.Done():
		return false, d.Stop()
	default:
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	var errs error
	for _, me := range d.managedExporters {
		if me.config.End == nil || me.config.End.After(time.Now()) {
			_, err := me.exporter.OnDecodedEvent(ctx, event)
			errs = errors.Join(errs, err)
		}
	}
	return false, errs
}

// Stop stops configuration watcher  and all managed flow log exporters.
func (d *dynamicExporter) Stop() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.watcher.Stop()

	var errs error
	for _, me := range d.managedExporters {
		errs = errors.Join(errs, me.exporter.Stop())
	}

	return errs
}

// NewDynamicExporter creates instance of dynamic hubble flow exporter.
func NewDynamicExporter(logger logrus.FieldLogger, configFilePath string, maxFileSizeMB, maxBackups int) *dynamicExporter {
	dynamicExporter := &dynamicExporter{
		logger:           logger,
		managedExporters: make(map[string]*managedExporter),
		maxFileSizeMB:    maxFileSizeMB,
		maxBackups:       maxBackups,
	}

	registerMetrics(dynamicExporter)

	watcher := NewConfigWatcher(configFilePath, dynamicExporter.onConfigReload)
	dynamicExporter.watcher = watcher
	return dynamicExporter
}

func (d *dynamicExporter) onConfigReload(ctx context.Context, hash uint64, config dynamicExportersConfig) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	configuredFlowLogNames := make(map[string]bool)
	for _, flowlog := range config.FlowLogs {
		configuredFlowLogNames[flowlog.Name] = true
		if _, ok := d.managedExporters[flowlog.Name]; ok {
			if d.applyUpdatedConfig(ctx, flowlog) {
				DynamicExporterReconfigurations.WithLabelValues("update").Inc()
			}
		} else {
			d.applyNewConfig(ctx, flowlog)
			DynamicExporterReconfigurations.WithLabelValues("add").Inc()
		}
	}

	for flowLogName := range d.managedExporters {
		if _, ok := configuredFlowLogNames[flowLogName]; !ok {
			d.applyRemovedConfig(flowLogName)
			DynamicExporterReconfigurations.WithLabelValues("remove").Inc()
		}
	}

	d.updateLastAppliedConfigGauges(hash)
}

func (d *dynamicExporter) applyNewConfig(ctx context.Context, flowlog *flowLogConfig) {
	exporterOpts := []exporteroption.Option{
		exporteroption.WithPath(flowlog.FilePath),
		exporteroption.WithMaxSizeMB(d.maxFileSizeMB),
		exporteroption.WithMaxBackups(d.maxBackups),
		exporteroption.WithAllowList(flowlog.IncludeFilters),
		exporteroption.WithDenyList(flowlog.ExcludeFilters),
		exporteroption.WithFieldMask(flowlog.FieldMask),
	}

	exporter, err := NewExporter(ctx, d.logger.WithField("flowLogName", flowlog.Name), exporterOpts...)
	if err != nil {
		d.logger.Errorf("Failed applying flowlog for name: %s; %v", flowlog.Name, err)
	}

	d.managedExporters[flowlog.Name] = &managedExporter{
		config:   flowlog,
		exporter: exporter,
	}

}

func (d *dynamicExporter) applyUpdatedConfig(ctx context.Context, flowlog *flowLogConfig) bool {
	m, ok := d.managedExporters[flowlog.Name]
	if ok && m.config.equals(flowlog) {
		return false
	}
	d.applyRemovedConfig(flowlog.Name)
	d.applyNewConfig(ctx, flowlog)
	return true
}

func (d *dynamicExporter) applyRemovedConfig(name string) {
	m, ok := d.managedExporters[name]
	if !ok {
		return
	}
	if err := m.exporter.Stop(); err != nil {
		d.logger.Errorf("error stopping exporter %v", err)
	}
	delete(d.managedExporters, name)
}

func (d *dynamicExporter) updateLastAppliedConfigGauges(hash uint64) {
	DynamicExporterConfigHash.WithLabelValues().Set(float64(hash))
	DynamicExporterConfigLastApplied.WithLabelValues().SetToCurrentTime()
}

type managedExporter struct {
	config   *flowLogConfig
	exporter FlowLogExporter
}
