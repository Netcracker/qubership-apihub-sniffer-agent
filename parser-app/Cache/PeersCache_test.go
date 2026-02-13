package Cache

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	peersCacheTestName = "disk_cache_test"
)

func TestNewPeersCache(t *testing.T) {
	pc := NewPeersCache(peersCacheTestName, nil)
	assert.NotNil(t, pc)
}
