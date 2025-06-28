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

package Cache

import (
	"crypto/md5"
	"fmt"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	log "github.com/sirupsen/logrus"
	"parser-app/db"
	"parser-app/entities"
)

type PacketCache interface {
	GetPacketCount() int
	StorePacket(packet entities.ParsedPacket, headersCache HttpHeadersCache) error
}

type packetCacheImpl struct {
	instance  libcache.Cache
	db        db.Connection
	captureId string
}

func NewPacketCache(captureId string, db db.Connection) PacketCache {
	nc := packetCacheImpl{instance: libcache.LRU.New(MinSize), db: db, captureId: captureId}
	nc.instance.SetTTL(DefaultAge)
	return &nc
}

func getPacketId(packet *entities.ParsedPacket) string {
	sPart := ""
	if packet.Peers[entities.DestPeer].Registered {
		sPart = entities.EndPointToString(packet.Peers[entities.DestPeer])
	} else {
		if packet.Peers[entities.SourcePeer].Registered {
			sPart = entities.EndPointToString(packet.Peers[entities.SourcePeer])
		} else {
			return ""
		}
	}
	//sPart += fmt.Sprintf(":%d:%s", packet.StreamId, packet.Timestamp.String())
	return fmt.Sprintf("%x", md5.Sum(append([]byte(sPart), packet.Payload...)))
}

func (p *packetCacheImpl) StorePacket(packet entities.ParsedPacket, headersCache HttpHeadersCache) error {
	var err error = nil
	packetId := getPacketId(&packet)
	if packetId == "" {
		return fmt.Errorf("invalid packet: %v", packet)
	}
	_, loaded := p.instance.Load(packetId)
	if loaded {
		return nil
	}
	packet.PeerId, err = p.db.GetPeerId(packet.Peers[0], packet.Peers[1], packet.ServiceName, p.captureId)
	if err != nil {
		log.Errorf("error getting peer id: %v", err)
		return err
	}
	headerIds := make([]string, 0)
	for k, v := range packet.Headers {
		hid := headersCache.GetHeaderId(k, v)
		if hid != "" {
			headerIds = append(headerIds, hid)
		}
	}
	packet.DbId, err = p.getPacketId(packet, p.captureId)
	if err != nil {
		log.Errorf("error getting packet id: %v", err)
		return err
	}
	err = p.db.SetPacketHeaders(packet.DbId, headerIds)
	if err != nil {
		log.Printf("error setting packet headers: %v", err)
	}
	packet.DbId, err = p.db.GetPacketId(packet, p.captureId)
	if err != nil {
		log.Printf("error storing packet id: %v", err)
	}
	p.instance.Store(packetId, packet)
	return nil
}

func (p *packetCacheImpl) getPacketId(packet entities.ParsedPacket, captureId string) (int, error) {
	var idv interface{}
	peerId, err := p.db.GetPeerId(packet.Peers[0], packet.Peers[1], packet.ServiceName, captureId)
	if err != nil {
		return -1, fmt.Errorf("unable to acquire peer id")
	}
	params := make([]interface{}, 6)
	params[0] = peerId
	params[1] = packet.SeqNo
	params[2] = packet.AckNo
	params[3] = packet.Timestamp.Unix()
	params[4] = packet.StrPayload
	params[5] = captureId
	for i := 0; i < 2; i++ {
		idv, err = p.db.GetScalarValue("SELECT Packet_id FROM Packets where Peer_id=$1 and Seq_No=$2 and Ack_no=$3 and Time_Stamp=$4 and Body=$5 and capture_id=$6", params)
		if err != nil {
			if i == 0 {
				params = append(params, packet.RequestUri)
				params = append(params, packet.RequestMethod)
				err = p.db.Execute("INSERT INTO Packets(Peer_id, Seq_No, Ack_no, Time_Stamp, Body, capture_id, Request_Uri, Request_Method) VALUES($1, $2, $3, $4, $5, $6, $7, $8)", params)
				if err != nil {
					return -2, err
				}
			} else {
				return -1, err
			}
		} else {
			iVal, err := db.VarToInt(idv)
			if err == nil {
				return iVal, nil
			} else {
				err = fmt.Errorf("unable to convert returned value '%v' to int: error %v", idv, err)
			}
			break
		}
	}
	return -3, fmt.Errorf("attempts exhausted")
}

func (p *packetCacheImpl) GetPacketCount() int {
	params := make([]interface{}, 1)
	params[0] = p.captureId
	idv, err := p.db.GetScalarValue("SELECT count(Packet_id) FROM Packets where capture_id=$1", params)
	if err != nil {
		return -1
	}
	iVal, err := db.VarToInt(idv)
	if err != nil {
		return -2
	}
	return iVal
}
