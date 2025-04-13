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

type CaptureServiceConfig struct {
	NetworkInterface      string // a network interface to gather packets on
	WorkDirectory         string // local path to store capture data
	SnapshotLen           int    // capture snapshot length (262144 by default)
	OutputFileCompression bool   // if true then capture data will be compressed during writing
	InstanceId            string // process instance ID for making distinctive capture files from different PODs
}
