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
	"sync"
	"time"
)

// CacheTTL internal constants
const CacheTTL = time.Second * 60

type CachedItem struct {
	LastUpdateTime time.Time
	UpdateLock     sync.Mutex
}

func (ca *CachedItem) NeedUpdate() bool {
	return time.Now().After(ca.LastUpdateTime)
}

func (ca *CachedItem) Update() {
	ca.UpdateLock.Lock()
	defer ca.UpdateLock.Unlock()
	ca.LastUpdateTime = time.Now().Add(CacheTTL)
}
