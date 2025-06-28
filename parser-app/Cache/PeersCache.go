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
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"parser-app/db"
	"parser-app/entities"
)

type PeersCache interface {
	GetId(src entities.EndPoint, dst entities.EndPoint, serviceName string) int
}
type peersCache struct {
	instance  libcache.Cache
	db        db.Connection
	captureId string
}

func NewPeersCache(captureId string, db db.Connection) PeersCache {
	nc := peersCache{instance: libcache.LRU.New(MinSize), db: db, captureId: captureId}
	nc.instance.SetTTL(DefaultAge)
	return &nc
}

func (nc *peersCache) GetId(src entities.EndPoint, dst entities.EndPoint, serviceName string) int {
	keyStr := entities.EndPointToString(src) + entities.EndPointToString(dst) + serviceName
	cachedHeaderId, exists := nc.instance.Load(keyStr)
	if exists {
		return cachedHeaderId.(int)
	}
	headerId, err := nc.db.GetPeerId(src, dst, serviceName, nc.captureId)
	if err != nil {
		return -1
	}
	nc.instance.Store(keyStr, headerId)
	return headerId
}
