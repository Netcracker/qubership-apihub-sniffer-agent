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
