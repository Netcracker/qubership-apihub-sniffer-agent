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
	"crypto/md5"
	"fmt"
	"testing"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	"github.com/stretchr/testify/assert"
)

const testApiKey = "123"
const testInternalKey = "456"
const testFilter = "filter"

func TestName(t *testing.T) {
	_, err := MakeCaptureInstanceConfig(view.CaptureRequest{}, testApiKey, testInternalKey)
	assert.NoError(t, err) // no conversion error on empty data
	extReq := view.CaptureRequest{
		Filter:      testFilter,
		Id:          fmt.Sprintf("%x", md5.New()),
		PacketCount: 1,
		Duration:    "1m30s",
		FileSize:    2,
		DateAndTime: view.EmptyString,
		CheckSum:    view.EmptyString,
		Namespace:   view.EmptyString,
		SnapshotLen: view.DefaultSnapLenBytes,
	}
	intReq, err := MakeCaptureInstanceConfig(extReq, testApiKey, testInternalKey)
	assert.NoError(t, err)                               // no conversion error
	assert.NotEqual(t, intReq.Status, VrGossipValidated) // status - not a gossip
	checkSum := view.GetRequestChecksum(extReq, testApiKey, testInternalKey)
	assert.NotEqual(t, intReq.CheckSum, checkSum)                      // checksum not match
	assert.Equal(t, intReq.Filter, testFilter)                         // filter is present
	assert.Equal(t, intReq.Duration, time.Minute+30*time.Second)       // duration converted
	er := ConvertToCaptureRequest(intReq, testApiKey, testInternalKey) // make a gossip
	assert.NotEqual(t, extReq, er)                                     // gossip is different
	// patch conversion result
	intReq.DateAndTime = time.Now()
	extReq.DateAndTime = intReq.DateAndTime.Format(dateFormat)
	extReq.CheckSum = view.GetRequestChecksum(extReq, testApiKey, testInternalKey) // now they're equal
	assert.Equal(t, extReq, er)
	// improper key order
	checkSum = view.GetRequestChecksum(extReq, testInternalKey, testApiKey)
	assert.NotEqual(t, extReq.CheckSum, checkSum)
	// no internal key set
	checkSum = view.GetRequestChecksum(extReq, testApiKey, view.EmptyString)
	assert.NotEqual(t, extReq.CheckSum, checkSum)
}
