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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type DiskCacheTest struct {
	Name    string `json:"service_name,omitempty"`
	Version string `json:"service_version,omitempty"`
}

const (
	cacheTestName = "disk_cache_test"
)

func TestNewDiskCache(t *testing.T) {
	dirName := os.TempDir()
	dc, err := NewDiskCache(cacheTestName, dirName)
	assert.NoError(t, err)
	assert.NotNil(t, dc)
	test1 := DiskCacheTest{cacheTestName, cacheTestName}
	jsonBytes, err := json.Marshal(test1)
	assert.NoError(t, err)
	assert.NotNil(t, jsonBytes)
	test2 := DiskCacheTest{}
	err = json.Unmarshal(jsonBytes, &test2)
	assert.NoError(t, err)
	assert.Equal(t, test1, test2)
	err = dc.StoreItem(cacheTestName, string(jsonBytes))
	assert.NoError(t, err)
	itemBytes, err := dc.GetItem(cacheTestName)
	assert.NoError(t, err)
	assert.NotNil(t, itemBytes)
	err = json.Unmarshal(itemBytes, &test2)
	assert.NoError(t, err)
	assert.Equal(t, test1, test2)
	err = dc.StoreItem(cacheTestName, cacheTestName)
	assert.NoError(t, err)
	itemString, err := dc.GetItemAsString(cacheTestName)
	assert.NoError(t, err)
	assert.Equal(t, itemString, cacheTestName)
	err = dc.Close()
	assert.NoError(t, err)
	files, err := os.ReadDir(dirName)
	assert.NoError(t, err)
	objCount := 0
	fmt.Print(dirName)
	for _, file := range files {
		if strings.HasPrefix(file.Name(), cacheTestName) {
			objCount++
		}
	}
	assert.Equal(t, 0, objCount)
}
