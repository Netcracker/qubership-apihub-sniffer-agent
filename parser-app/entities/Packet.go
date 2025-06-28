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

type EthernetFrame [14]byte // just to skip

// IPv4Header
// follows EthernetFrame, looks like a fixed size
type IPv4Header struct {
	IPV             byte   // IP version + header len
	DSF             byte   // just skip it
	TotalLengh      uint16 // packet length
	Flags           byte
	TTL             byte
	Protocol        byte // 6 = TCP
	HeaderCheckSum  uint16
	SourceAddr      [4]byte
	DestinationAddr [4]byte
}

// TCPHeader
// follows EthernetFrame
type TCPHeader struct {
	SourcePort           int16
	DestinationPort      int16
	SequenceNumber       uint32
	AcknowlegementNumber uint32
	Flags                uint16
	Window               uint16
	Checksum             uint16
	UrgentPointer        uint16
	Options              [12]byte
}

type PacketFixed struct {
	EthernetFrame
	IPv4Header
}

type PayLoadAddr struct {
	Source      EndPoint
	Destination EndPoint
}

type PayLoadString struct {
	PayLoadAddr
	PayLoad string
}

type PayLoadBytes struct {
	PayLoadAddr
	PayLoad []byte
}
