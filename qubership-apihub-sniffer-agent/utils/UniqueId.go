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

package utils

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// MakeUniqueId
// makes UUID
func MakeUniqueId() string {
	defer func() {
		if x := recover(); x != nil {
			log.Error("make unique Id in recover, caught error====================", x)
		}
	}()
	return uuid.NewString()
}
