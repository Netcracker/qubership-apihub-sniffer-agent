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

package disk_cache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	"github.com/akrylysov/pogreb"
	log "github.com/sirupsen/logrus"
)

const (
	ErrorCacheIsNil           = "current cache for %s is nil"
	ErrorCacheLookup          = "cache %s lookup failed for key %s. Error %v"
	ErrorCacheDelete          = "cache %s failed to delete key %s. Error %v"
	ErrorCacheStore           = "cache %s failed to store item under key %s. Error %v"
	ErrorIteratorIsNil        = "returned cache %s iterator is nil"
	ErrorCurrentIteratorIsNil = "current cache %s iterator is nil"
	ErrorCacheKeyNotInvalid   = "invalid cache key for %s"
)

type DiskCache interface {
	Iterate() (interface{}, error)
	IterateItemBytes(iterator interface{}) (string, []byte, error)
	IterateItem(iterator interface{}) (string, string, error)
	StoreItem(CacheKey string, valueStr string) error
	Sync() int
	Count() int
	GetItem(cacheKey string) ([]byte, error)
	GetItemAsString(cacheKey string) (string, error)
	Close() error
	NilIteratorError() error
}

// diskCache
// implementation for public interface
type diskCache struct {
	db               *pogreb.DB
	cacheName        string
	cacheDir         string
	uuid             string
	nilIteratorError error
}

// NewDiskCache
// creates a new instance
func NewDiskCache(cacheName string, cacheDir string) (DiskCache, error) {
	uuidString := utils.MakeUniqueId()
	if cacheDir == view.EmptyString {
		cacheDir = os.TempDir()
	}
	cachePath := filepath.Join(cacheDir, cacheName+uuidString)
	cacheInstance, err := pogreb.Open(cachePath, nil)
	if err != nil {
		return nil, err
	}
	return &diskCache{
		db:               cacheInstance,
		cacheName:        cacheName,
		cacheDir:         cachePath,
		uuid:             uuidString,
		nilIteratorError: fmt.Errorf(ErrorCurrentIteratorIsNil, cacheName),
	}, nil
}

// Iterate
// opens an iterator over the cache
func (cache *diskCache) Iterate() (interface{}, error) {
	if cache != nil {
		iterator := cache.db.Items()
		if iterator == nil {
			return iterator, fmt.Errorf(ErrorIteratorIsNil, cache.cacheName)
		}
		return iterator, nil
	}
	return nil, fmt.Errorf(ErrorCacheIsNil, "")
}

// IterateItem
// move to the next iterated item
// calls IterateItemBytes and returns string value
func (cache *diskCache) IterateItem(iterator interface{}) (string, string, error) {
	key, val, err := cache.IterateItemBytes(iterator)
	return key, string(val), err
}

// IterateItemBytes
// move to the next iterated item
func (cache *diskCache) IterateItemBytes(iterator interface{}) (string, []byte, error) {
	if iterator != nil {
		itr := iterator.(*pogreb.ItemIterator)
		key, val, err := itr.Next()
		return string(key), val, err
	}
	return view.EmptyString, nil, cache.nilIteratorError
}

// StoreItem
// store item in cache
func (cache *diskCache) StoreItem(CacheKey string, valueStr string) error {
	if len(CacheKey) < 1 && len(valueStr) < 1 {
		return nil
	}
	if cache == nil {
		return fmt.Errorf(ErrorCacheIsNil, CacheKey)
	}
	if len(CacheKey) < 1 {
		return fmt.Errorf(ErrorCacheKeyNotInvalid, cache.cacheName)
	}
	key := []byte(CacheKey)
	found, err := cache.db.Has(key)
	if err == nil && found {
		err = cache.db.Delete(key)
		if err != nil {
			err = fmt.Errorf(ErrorCacheDelete, cache.cacheName, CacheKey, err)
		}
	} else {
		if err != nil {
			err = fmt.Errorf(ErrorCacheLookup, cache.cacheName, CacheKey, err)
		}
	}
	if err == nil {
		err = cache.db.Put(key, []byte(valueStr))
		if err != nil {
			err = fmt.Errorf(ErrorCacheStore, cache.cacheName, CacheKey, err)
		}
	}
	return err
}

// Sync
// flush cache data on disk
func (cache *diskCache) Sync() int {
	if cache.db != nil {
		if cache.db.Sync() == nil {
			return int(cache.db.Count())
		}
	}
	return -1
}

// Count
// returns cached item count
func (cache *diskCache) Count() int {
	if cache.db != nil {
		return int(cache.db.Count())
	}
	return -1
}

// GetItem
// returns item value as byte array
func (cache *diskCache) GetItem(cacheKey string) ([]byte, error) {
	if cache.db == nil {
		return nil, fmt.Errorf(ErrorCacheIsNil, cache.cacheName)
	}
	if cacheKey != view.EmptyString {
		key := []byte(cacheKey)
		val, err := cache.db.Get(key)
		if err != nil {
			return nil, err
		}
		return val, nil
	}
	return nil, fmt.Errorf(ErrorCacheKeyNotInvalid, cache.cacheName)
}

// GetItemAsString
// returns item value as string
func (cache *diskCache) GetItemAsString(cacheKey string) (string, error) {
	val, err := cache.GetItem(cacheKey)
	if err == nil && val != nil {
		return string(val), err
	}
	return view.EmptyString, err
}

// Close
// dispose cache and remove underlying files
func (cache *diskCache) Close() error {
	var err error
	if cache.db != nil {
		recCnt := cache.db.Count()
		err = cache.db.Close()
		if err == nil {
			log.Debugf("Cache %s closed (%d)", cache.cacheName, recCnt)
			cache.db = nil
			if _, err = os.Stat(cache.cacheDir); err == nil {
				err = os.RemoveAll(cache.cacheDir)
				if err != nil {
					err = fmt.Errorf("unable to delete cache files at '%s'. Error: %v", cache.cacheDir, err)
				}
			} else {
				if !errors.Is(err, os.ErrNotExist) {
					err = fmt.Errorf("cache path does not exist '%s'. Error: %v", cache.cacheDir, err)
				}
			}
			return err
		}
	}
	return fmt.Errorf(ErrorCacheIsNil, cache.cacheName)
}

// NilIteratorError
// returns specific error for comparison
func (cache *diskCache) NilIteratorError() error {
	return cache.nilIteratorError
}
