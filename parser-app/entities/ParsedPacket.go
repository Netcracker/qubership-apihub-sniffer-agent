package entities

import (
	"time"
)

const (
	SourcePeer = 0
	DestPeer   = 1
)

type ParsedPacket struct {
	DbId          int
	Peers         []EndPoint
	PeerId        int
	Timestamp     time.Time
	SeqNo         int
	AckNo         int
	Payload       []byte
	StrPayload    string
	ServiceName   string
	Headers       map[string]string
	RequestUri    string
	RequestMethod string
}
