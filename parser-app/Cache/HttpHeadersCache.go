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
	"fmt"
	"github.com/shaj13/libcache"
	_ "github.com/shaj13/libcache/lru"
	"parser-app/db"
	"parser-app/entities"
	"time"
)

const (
	MinSize    = 100
	DefaultAge = 6 * time.Hour
)

type HttpHeadersCache interface {
	GetHeaderId(key, value string) string
}
type httpHeadersCache struct {
	instance libcache.Cache
	db       db.Connection
}

func (hc *httpHeadersCache) StorePacket(_ entities.ParsedPacket, _ HttpHeadersCache) error {
	//TODO implement me
	panic("implement me")
}

func NewHttpHeadersCache(db db.Connection) HttpHeadersCache {
	nc := httpHeadersCache{instance: libcache.LRU.New(MinSize), db: db}
	nc.instance.SetTTL(DefaultAge)
	// register expiration callback
	return &nc
}

func (hc *httpHeadersCache) GetHeaderId(key, value string) string {
	cachedHeaderId, exists := hc.instance.Load(key + value)
	if exists {
		return fmt.Sprint(cachedHeaderId)
	}
	headerId, err := hc.db.GetHeaderId(key, value)
	if err != nil {
		return ""
	}
	hc.instance.Store(key+value, headerId)
	return headerId
}
