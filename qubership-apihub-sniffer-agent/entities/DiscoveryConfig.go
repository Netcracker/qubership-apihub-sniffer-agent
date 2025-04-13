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
	"os"
	"path"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	log "github.com/sirupsen/logrus"
)

const (
	KubeConfigOff = "off"
	KubeConfigOn  = "on"
)

type KubernetesConfig struct {
	Kubeconfig          string // kubectl configuration mostly $HOME/.kube/config
	KubeNameSpace       string // a namespace name from the kubectl configuration
	KubeSecurityContext string // a security context (almost equals to credentials) from the kubectl configuration
	KubeNodeNamePrefix  string // a POD's name prefix to filter POD list
}

type NotificationConfig struct {
	KubernetesConfig
	APIkey        string            // endpoint's API key
	EndPointPort  int               // and endpoint port to compute the request address
	EndPointProto string            // an endpoint protocol (http:// or https://) to compute the request address
	AddrList      map[string]string // a local address list to prevent self notifications
	InternalKey   string            // a value for additional gossips protection
}

// ValidateKubeConfig
// validates value for kube config
// returns true if kube interface turned on, false when turned off and error
func ValidateKubeConfig(kubeConfig string, makeDefPath bool) (string, error) {
	if kubeConfig == KubeConfigOff {
		return kubeConfig, nil
	}
	if kubeConfig == KubeConfigOn {
		return kubeConfig, nil
	}
	if kubeConfig == view.EmptyString {
		if !makeDefPath {
			return KubeConfigOn, nil
		}
		home := os.Getenv("HOME")
		if home == view.EmptyString {
			home = "."
		}
		kubeConfig = path.Join(home, ".kube", "config") // try to make alternative name
	}
	fh, err := os.Open(kubeConfig)
	defer func(fh *os.File) {
		err := fh.Close()
		if err != nil {
			log.Warnf("unable to close kubernetes config file %s:%v", kubeConfig, err)
		}
	}(fh)
	return kubeConfig, err
}
