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

import "time"

const (
	EmptyString  = ""
	GzipSuffix   = ".gz"
	ApiKeyHeader = "api-key"
	// DefaultFileDataSize packet data size (without header) stored in a single file
	DefaultFileDataSize = 681574400 // 650M per file by default
	// DefaultCaptureDuration default capture duration instead of pcap.BlockForever
	DefaultCaptureDuration = time.Second * 60
	MinCaptureDuration     = time.Second * 15
	// CaptureInterfaceAny a synonym for all interfaces at the host
	CaptureInterfaceAny = "any"
	// CaptureInterfaceDetect use the first interface with an IPv4 or IPv6 address
	CaptureInterfaceDetect = "auto"
	// DefaultSnapLenBytes The same default as tcpdump.
	DefaultSnapLenBytes = 256 * 1024
	// ArrayJoinSeparator a separator to use with strings.Join
	ArrayJoinSeparator = ","
	// FilterMaxLength a limit to capture filter length. Sniffer agent will fail when filter bigger than this size
	FilterMaxLength = 64 * 1024
)
