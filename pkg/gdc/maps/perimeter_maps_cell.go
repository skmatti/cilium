package maps

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/google_ctmap"
	"github.com/cilium/cilium/pkg/maps/perimetermap"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "perimeter-gc")
)

var Cell = cell.Module(
	"gdc-ag-map-initializer",
	"GDC-AG Map Initializer",

	cell.Provide(InitalizeGDCMaps),
)

type GDCMapsResult struct {
	PerimeterRedirectMapIP *bpf.Map
	PerimeterRedirectMapID *bpf.Map
	GoogleCtMapID          *bpf.Map
}

func InitalizeGDCMaps() *GDCMapsResult {
	result := &GDCMapsResult{}

	createPerimeterMaps(result)

	return result
}

func createPerimeterMaps(result *GDCMapsResult) {
	if !features.GlobalConfig.EnableGatewayIPFromAnnotation {
		return
	}

	log.Info("creating IP to ID perimeter map...")

	perimeterRedirectIPtoIDMap := perimetermap.InitRedirectEPIPMap4()

	if err := perimeterRedirectIPtoIDMap.OpenOrCreate(); err != nil {
		log.Infof("error while creating/opening IP to ID perimeter map: %v", err)
	}

	log.Info("creating ID to IP perimeter map...")

	perimeterRedirectIDtoIPMap := perimetermap.InitRedirectEPIDMap4()

	if err := perimeterRedirectIDtoIPMap.OpenOrCreate(); err != nil {
		log.Infof("error while creating/opening ID to IP perimeter map: %v", err)
	}

	log.Info("finished creating perimeter maps...")

	log.Info("creating ID to google ctmap...")

	googleCtMap := google_ctmap.InitGoogleCtMap()

	if err := googleCtMap.OpenOrCreate(); err != nil {
		log.Infof("error while creating/opening google ctmap: %v", err)
	}

	log.Info("finished creating google ctmap...")

	if !option.Config.RestoreState {
		log.Info("clearing perimeter map state...")

		perimeterRedirectIDtoIPMap.DeleteAll()
		perimeterRedirectIPtoIDMap.DeleteAll()
		googleCtMap.DeleteAll()
	}

	result.PerimeterRedirectMapID = perimeterRedirectIPtoIDMap
	result.PerimeterRedirectMapIP = perimeterRedirectIDtoIPMap
	result.GoogleCtMapID = googleCtMap
}
