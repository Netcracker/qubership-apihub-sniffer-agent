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
