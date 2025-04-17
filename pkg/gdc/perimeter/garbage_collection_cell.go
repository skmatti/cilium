package perimeter

import (
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"

	gdcmaps "github.com/cilium/cilium/pkg/gdc/maps"

	perimetergc "github.com/cilium/cilium/pkg/maps/perimetermap/gc"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "perimeter-gc")
)

var Cell = cell.Module(
	"perimeter-gc-reconciler",
	"Perimeter GC Reconciler",

	cell.Invoke(initPerimeterGarbageCollection),
)

type perimeterGCParams struct {
	cell.In

	GoogleConfig features.Config
}

func initPerimeterGarbageCollection(perimeterMapsResult *gdcmaps.GDCMapsResult, params perimeterGCParams) error {
	if !features.GlobalConfig.EnableGatewayIPFromAnnotation {
		log.Info("perimeter gc reconciler not enabled, not starting reconciler...")
		return nil
	}

	log.Info("perimeter gc reconciler has started...")

	perimetergc.Enable(params.GoogleConfig.PerimeterMapsGCIntervalSeconds, perimeterMapsResult)

	return nil
}
