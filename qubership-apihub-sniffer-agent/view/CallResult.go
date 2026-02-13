package view

type RequestStatus string
type CaptureState int

// Status storage type constants
const (
	CapStateNone CaptureState = iota
	CapStateRunning
	CapStateFailed
	CapStateStopped
	CapStateCompleted
	CapStateStopping
	CapStateStarting
)

// Status constant values
const (
	RequestStatusNone      RequestStatus = "NONE"
	RequestStatusRunning   RequestStatus = "STARTED"
	RequestStatusFailed    RequestStatus = "FAILED"
	RequestStatusStopped   RequestStatus = "STOPPED"
	RequestStatusCompleted RequestStatus = "COMPLETED"
	RequestStatusStopping  RequestStatus = "STOPPING"
	RequestStatusStarting  RequestStatus = "STARTING"
)

type CallResult struct {
	Status RequestStatus `json:"status,omitempty"`
	Id     string        `json:"id,omitempty"`
}

// CapStateToReqStatus
// converts int status to text
func CapStateToReqStatus(status CaptureState) RequestStatus {
	switch status {
	case CapStateStopped:
		return RequestStatusStopped
	case CapStateRunning:
		return RequestStatusRunning
	case CapStateFailed:
		return RequestStatusFailed
	case CapStateCompleted:
		return RequestStatusCompleted
	case CapStateStopping:
		return RequestStatusStopping
	case CapStateStarting:
		return RequestStatusStarting
	default:
		break
	}
	return RequestStatusNone
}
