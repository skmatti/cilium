package config

import (
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

const (
	enableGDCILB                   = "enable-gdc-ilb"
	googleCMDisableCiliumNodeSync  = "google-cm-disable-cilium-node-sync"
	googleCMOverrideIdentityLabels = "google-cm-override-identity-labels"
	googleCMServiceNamespaceLabels = "google-cm-service-namespace-labels"
	googleCMEndpointLabelSelectors = "google-cm-endpoint-selectors"
)

var (
	overrideLabelsValidator = option.Validator(func(val string) (string, error) {
		for _, kv := range strings.Split(val, ",") {
			labelEntry := strings.Split(kv, "=")
			if len(labelEntry) != 2 {
				return "", fmt.Errorf(`invalid label %q, expecting "<label-key>=<label-value>"`, kv)
			}
			label := labels.ParseLabel(kv)
			if !label.IsValid() {
				return "", fmt.Errorf(`label key is empty for label %q`, kv)
			}
			if label.IsReservedSource() {
				return "", fmt.Errorf(`label %q must not have reserved source`, kv)
			}
		}
		return val, nil
	})
)

// GoogleConfig contains Google-specific clustermesh configuration.
type GoogleConfig struct {
	EnableGDCILB           bool              `mapstructure:"enable-gdc-ilb"`
	DisableCiliumNodeSync  bool              `mapstructure:"google-cm-disable-cilium-node-sync"`
	OverrideIdentityLabels map[string]string `mapstructure:"google-cm-override-identity-labels"`
	ServiceNamespaceLabels []string          `mapstructure:"google-cm-service-namespace-labels"`
	EndpointLabelSelectors []string          `mapstructure:"google-cm-endpoint-selectors"`
}

// DefaultGoogleConfig represents the default configuration.
var DefaultGoogleConfig = GoogleConfig{
	EnableGDCILB:           false,
	DisableCiliumNodeSync:  false,
	OverrideIdentityLabels: make(map[string]string),
	ServiceNamespaceLabels: []string{},
	EndpointLabelSelectors: []string{},
}

// Flags implements the cell.Flagger interface, to register the given flags.
func (cfg GoogleConfig) Flags(flags *flag.FlagSet) {
	flags.Bool(enableGDCILB, cfg.EnableGDCILB, "Enable Google GDC ILB support")
	flags.MarkHidden(enableGDCILB)

	flags.Bool(googleCMDisableCiliumNodeSync, cfg.DisableCiliumNodeSync, "Disable syncing of CiliumNode resources to the clustermesh")
	flags.MarkHidden(googleCMDisableCiliumNodeSync)

	flags.Var(option.NewNamedMapOptions(googleCMOverrideIdentityLabels, &cfg.OverrideIdentityLabels, overrideLabelsValidator), googleCMOverrideIdentityLabels, "Key-value pairs of labels to add to exported cilium identities")
	flags.MarkHidden(googleCMOverrideIdentityLabels)

	flags.StringSlice(googleCMServiceNamespaceLabels, cfg.ServiceNamespaceLabels, "List of namespace labels to enable clustermesh distribution for (empty means all namespaces are distributed)")
	flags.MarkHidden(googleCMServiceNamespaceLabels)

	flags.StringSlice(googleCMEndpointLabelSelectors, cfg.EndpointLabelSelectors,
		"List of endpoint label selectors to enable clustermesh distribution for. An endpoint must comply with at least one of the label selectors to be distributed. For e.g. k1,!k2 k3=v3 selects endpoints that have the label key k1, as well as endpoints that have the key-value pair k3=v3 and do not have the key k2.")
	flags.MarkHidden(googleCMEndpointLabelSelectors)
}
