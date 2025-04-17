package gc

import (
	"github.com/cilium/cilium/pkg/time"

	gdcmaps "github.com/cilium/cilium/pkg/gdc/maps"
	perimeterconst "github.com/cilium/cilium/pkg/maps/perimetermap/consts"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/perimetermap"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "perimeter-redirect-gc")

// staleCounts maps an endpoint ID to the number of consecutive GC cycles in which it was found inactive.
var staleCounts = make(map[uint16]int)

// deleteThreshold is the number of consecutive GC cycles an entry must be marked stale before it is deleted.
const (
	deleteThreshold = 2
)

// Enable launches the GC process. It runs the GC immediately on startup and then every 30 minutes.
func Enable(intervalSeconds int, perimeterMapsResult *gdcmaps.GDCMapsResult) {
	go func() {
		ticker := time.NewTicker(time.Duration(intervalSeconds) * time.Second)
		defer ticker.Stop()

		log.Infof("Running initial perimeter maps GC: %s, with interval: %d seconds", time.Now().Format(time.RFC3339), intervalSeconds)
		runGC(perimeterMapsResult)

		for {
			select {
			case <-ticker.C:
				log.Infof("Running perimeter maps gc: %s", time.Now().Format(time.RFC3339))
				runGC(perimeterMapsResult)
			}
		}
	}()
}

// runGC performs the following steps:
//  1. Scans the IPv4 global CT maps to build a set of active endpoint IDs if connection is DSR enabled.
//  2. Scans the RedirectEPIPMap4 map and, for each entry, if its endpoint ID is not active,
//     increments a stale count.
//     If the stale count reaches deleteThreshold, the entry is marked for deletion.
//  3. For each marked (stale) entry, deletes the entry from RedirectEPIPMap4 and the corresponding reverse entry
//     from RedirectEPIDMap4.
//  4. If an entry is active, its stale count is reset.
func runGC(perimeterMaps *gdcmaps.GDCMapsResult) {
	activeEPIDs := make(map[uint16]bool)
	ctMaps := ctmap.GlobalMaps(true, false)
	for _, m := range ctMaps {
		if err := m.Open(); err != nil {
			log.WithError(err).Warn("Failed to open CT map")
			continue
		}

		m.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
			entry, ok := value.(*ctmap.CtEntry)
			if !ok {
				return
			}

			if (entry.Flags & ctmap.DSRInternal) != 0 {
				epID := entry.RevNAT
				activeEPIDs[epID] = true
			}
		})
		m.Close()
	}

	log.Debugf("Active endpoint IDs from CT maps: %d", len(activeEPIDs))

	ipMap := perimeterMaps.PerimeterRedirectMapIP

	staleEntriesMap := make(map[uint16]struct {
		key   bpf.MapKey
		value bpf.MapValue
	})
	if err := ipMap.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		epKey, ok := key.(*perimetermap.RedirectEP4IDKey)
		if !ok {
			return
		}
		if _, active := activeEPIDs[epKey.Data.ID]; !active {
			// Increment the stale count since endpoint ID is not active.
			staleCounts[epKey.Data.ID]++
			log.Debugf("Entry %d not active, stale count: %d", epKey.Data.ID, staleCounts[epKey.Data.ID])
			if staleCounts[epKey.Data.ID] >= deleteThreshold {
				// Only mark for deletion if the stale count has reached 2.
				staleEntriesMap[epKey.Data.ID] = struct {
					key   bpf.MapKey
					value bpf.MapValue
				}{key.New(), value.New()}
			}
		} else {
			// The entry is active; reset its stale count.
			if _, found := staleCounts[epKey.Data.ID]; found {
				delete(staleCounts, epKey.Data.ID)
				log.Debugf("Entry %d is active; resetting stale count", epKey.Data.ID)
			}
		}
	}); err != nil {
		log.WithError(err).Warnf("Error dumping %s", perimeterconst.RedirectEPIPMap4Name)
	}
	if len(staleEntriesMap) == 0 {
		return
	}

	log.Infof("Found %d stale entries in RedirectEPIPMap4", len(staleEntriesMap))

	for epID, pair := range staleEntriesMap {
		if err := ipMap.Delete(pair.key); err != nil {
			// If the element is already missing, log a debug message.
			log.Warningf("Failed to delete stale entry for %d from RedirectEPIPMap4 (possibly already deleted): %v", epID, err)
		}

		idMap := perimeterMaps.PerimeterRedirectMapID
		idKey, ok := pair.value.(*perimetermap.RedirectEP4IPValue)
		if !ok {
			log.Info("Failed to convert pair.value to *perimetermap.RedirectEP4IP")
			continue
		}
		if err := idMap.Delete(idKey.Data.ToKey()); err != nil {
			log.Warningf("Failed to delete stale entry for %v from RedirectEPIDMap4 (possibly already deleted): %v", idKey, err)
		}

		delete(staleCounts, epID)
	}
}
