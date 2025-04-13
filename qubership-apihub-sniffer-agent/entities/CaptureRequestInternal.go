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

package entities

import (
	"strings"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	log "github.com/sirupsen/logrus"
)

type ValidationResult int

const (
	VrNotValid ValidationResult = iota
	VrIdEmpty
	VrCheckSumEmpty
	VrDateTimeEmpty
	VrCheckSumNotMatch
	VrGossipValidated
)
const (
	dateFormat = "2006-01-02T15:04:05"
)

// CaptureInstanceConfig
// capture request parameters for internal usage
type CaptureInstanceConfig struct {
	CaptureServiceConfig
	Filter      string
	Id          string
	PacketCount int
	Duration    time.Duration
	FileSize    int
	DateAndTime time.Time
	CheckSum    string
	Status      ValidationResult
	Namespaces  []string
}

// MakeCaptureInstanceConfig
// converts externally sent input parameters into internally used
func MakeCaptureInstanceConfig(request view.CaptureRequest, apiKey, internalKey string) (CaptureInstanceConfig, error) {
	var err error
	ret := CaptureInstanceConfig{
		CaptureServiceConfig: CaptureServiceConfig{SnapshotLen: request.SnapshotLen, NetworkInterface: request.CaptureDevice},
		Filter:               request.Filter,
		Id:                   request.Id,
		Duration:             view.DefaultCaptureDuration,
		PacketCount:          request.PacketCount,
		FileSize:             request.FileSize,
		Status:               VrNotValid,
		Namespaces:           request.Namespaces,
	}
	if ret.FileSize <= 0 {
		ret.FileSize = view.DefaultFileDataSize
	}
	if ret.SnapshotLen <= 0 {
		ret.SnapshotLen = view.DefaultSnapLenBytes
	}
	if request.Duration != view.EmptyString {
		ret.Duration, err = time.ParseDuration(request.Duration)
	} else {
		ret.Duration = view.DefaultCaptureDuration
	}
	if err == nil && len(request.DateAndTime) >= len(dateFormat) {
		ret.DateAndTime, err = time.Parse(dateFormat, request.DateAndTime)
	}
	if err == nil {
		if request.CheckSum != view.EmptyString {
			ret.CheckSum = request.CheckSum
		}
		computedSum := view.GetRequestChecksum(request, apiKey, internalKey)
		ret.Status = validateRequest(ret, computedSum)
	}
	return ret, err
}

// ConvertToCaptureRequest
// converts internal parameters to external representation
func ConvertToCaptureRequest(request CaptureInstanceConfig, apiKey, internalKey string) view.CaptureRequest {
	ret := view.CaptureRequest{
		Filter:        request.Filter,
		Id:            request.Id,
		PacketCount:   request.PacketCount,
		Duration:      request.Duration.String(),
		FileSize:      request.FileSize,
		Namespaces:    request.Namespaces,
		CaptureDevice: request.NetworkInterface,
		SnapshotLen:   request.SnapshotLen,
	}
	if time.Now().Sub(request.DateAndTime) < time.Minute {
		ret.DateAndTime = request.DateAndTime.Format(dateFormat)
	} else {
		request.DateAndTime = time.Now()
		ret.DateAndTime = request.DateAndTime.Format(dateFormat)
	}
	ret.CheckSum = view.GetRequestChecksum(ret, apiKey, internalKey)
	return ret
}

// validateRequest
// performs checksum validation against the request contents
func validateRequest(req CaptureInstanceConfig, computedSum string) ValidationResult {
	if req.Id == view.EmptyString {
		return VrIdEmpty
	}
	if req.CheckSum == view.EmptyString {
		return VrCheckSumEmpty // request ID and checksum must have values
	}
	tNow := time.Now()
	if tNow.After(req.DateAndTime) {
		if computedSum == req.CheckSum {
			return VrGossipValidated
		} else {
			log.Debugf("computed:%s, received:%s", computedSum, req.CheckSum)
			return VrCheckSumNotMatch
		}
	} else {
		log.Debugf("improper date alignment now:%s, received:'%s'", tNow.String(), req.DateAndTime.String())
	}
	return VrDateTimeEmpty
}

func CaptureConfigurationEqual(cfg1, cfg2 CaptureInstanceConfig) bool {
	return cfg1.Status == cfg2.Status &&
		cfg1.Duration == cfg2.Duration &&
		cfg1.Filter == cfg2.Filter &&
		cfg1.FileSize == cfg2.FileSize &&
		cfg1.PacketCount == cfg2.PacketCount &&
		strings.Join(cfg1.Namespaces, view.ArrayJoinSeparator) == strings.Join(cfg2.Namespaces, view.ArrayJoinSeparator) &&
		cfg1.NetworkInterface == cfg2.NetworkInterface &&
		cfg1.SnapshotLen == cfg2.SnapshotLen
}
