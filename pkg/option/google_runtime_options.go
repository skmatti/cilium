package option

import "fmt"

const (
	GoogleServiceSteeringDataPath = "GoogleServiceSteeringDataPath"
)

var (
	specGoogleServiceSteeringDataPath = Option{
		Define:      "ENABLE_GOOGLE_SERVICE_STEERING",
		Description: "Enable Google Service Steering Data Path",
		Verify:      verifyGoogleServiceSteeringDataPath,
	}
)

func verifyGoogleServiceSteeringDataPath(key, value string) error {
	if !Config.EnableGoogleServiceSteering {
		return fmt.Errorf("GoogleServiceSteeringDataPath option is only available if --enable-google-service-steering")
	}
	return nil
}
