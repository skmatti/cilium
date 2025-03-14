package cmd

import (
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/afero"
)

func (d *Daemon) initGoogleModulesBeforeEndpointRestore() {
	featureConfig := features.GlobalConfig

	if featureConfig.EnableGoogleBPFGeneve {
		if option.Config.DirectRoutingDevice == "" {
			log.Fatal("Direct Routing Device is not detected. It is required by Google VPC feature")
		}
		sysctl := sysctl.NewDirectSysctl(afero.NewOsFs(), "/proc")
		// Disable rp_filter on the direct routing device, so that decapped GENEVE packet won't be dropped by kernel.
		if err := connector.DisableRpFilter(sysctl, option.Config.DirectRoutingDevice); err != nil {
			log.WithError(err).Fatalf("Failed to disable rp_filter on direct routing device %s", option.Config.DirectRoutingDevice)
		}
		// Enable accept_local on the direct routing device. This is needed for hairpin flows.
		sysSettings := []tables.Sysctl{
			{
				Name:      []string{"net", "ipv4", "conf", option.Config.DirectRoutingDevice, "accept_local"},
				Val:       "1",
				IgnoreErr: false,
			},
		}
		if err := sysctl.ApplySettings(sysSettings); err != nil {
			log.WithError(err).WithField("interface", option.Config.DirectRoutingDevice).Fatal("apply sysctl on direct routing interface")
		}
	}
}
