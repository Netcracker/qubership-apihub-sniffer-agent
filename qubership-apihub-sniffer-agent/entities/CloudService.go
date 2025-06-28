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
	"encoding/json"
)

const ServiceVersionLabel = "app.kubernetes.io/version"

// CloudService
// cloud service entry (Name + Version)
type CloudService struct {
	Name      string `json:"service_name,omitempty"`
	PodName   string `json:"pod_name,omitempty"`
	Version   string `json:"service_version,omitempty"`
	NameSpace string `json:"service_namespace,omitempty"`
}

// UnmarshallCloudService
// converts bytes into CloudService value
func UnmarshallCloudService(svrEnt *CloudService, bytes []byte) error {
	return json.Unmarshal(bytes, svrEnt)
}
