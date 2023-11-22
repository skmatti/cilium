package option

const (
	GoogleServiceSteeringDataPath = "GoogleServiceSteeringDataPath"
)

var (
	specGoogleServiceSteeringDataPath = Option{
		Define:      "ENABLE_GOOGLE_SERVICE_STEERING",
		Description: "Enable Google Service Steering Data Path",
	}
)
