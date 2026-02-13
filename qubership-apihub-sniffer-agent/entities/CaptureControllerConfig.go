package entities

// CaptureControllerConfig
// configuration for capture controller
type CaptureControllerConfig struct {
	APIkey         string // API key to validate client's requests
	InternalKey    string // internal key to validate gossip requests
	ProductionMode bool   // production mode flag
}
