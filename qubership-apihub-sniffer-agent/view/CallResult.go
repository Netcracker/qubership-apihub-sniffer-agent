// Copyright 2024-2025 NetCracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
