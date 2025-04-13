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

package neighbour

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/kube_service"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	log "github.com/sirupsen/logrus"
	"gopkg.in/resty.v1"
)

type NotificationSender interface {
	NotifyAll(req view.CaptureRequest, bStart bool) error
	GetNodeList() ([]string, error)
	GetNamespaceList() ([]string, error)
}

// notifierImpl
// underline Discovery interface implementation
type notifierImpl struct {
	entities.NotificationConfig                        // configuration
	nodeList                    []string               // cached list of nodes
	ks                          kube_service.K8Service // kubernetes interface
	locals                      map[string]string      // local address map
	unlockTime                  time.Time
}

// notificationParams
// parameters to notify exact node
type notificationParams struct {
	requestURI string // full fledged request address e.g. http://<hostname>:<port></path>
	podAddr    string // pod address (since it is also required)
}

// common functions

// NewNotificationSender
// creates an interface instance
func NewNotificationSender(configuration entities.NotificationConfig, ks kube_service.K8Service, locals map[string]string) NotificationSender {
	if configuration.AddrList == nil {
		configuration.AddrList = make(map[string]string)
	}
	d := &notifierImpl{
		NotificationConfig: configuration,
		nodeList:           make([]string, 0),
		ks:                 ks,
		locals:             locals,
	}
	return d
}

// makeRequest
// makes a gossip/notification request
func makeRequest(nodeName string, apiKey string) *resty.Request {
	tr := http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	cl := http.Client{Transport: &tr, Timeout: time.Second * 60}

	client := resty.NewWithClient(&cl)
	client.SetRedirectPolicy(resty.DomainCheckRedirectPolicy(nodeName))
	req := client.R()
	if apiKey != "" {
		req.SetHeader(view.ApiKeyHeader, apiKey)
	}

	return req
}

// notifyNode
// send notification request to node
func notifyNode(params notificationParams, cr view.CaptureRequest, apiKey string, wg *sync.WaitGroup) {
	defer wg.Done()
	req := makeRequest(params.podAddr, apiKey)
	var err error
	req.Body, err = json.Marshal(cr)
	if err != nil {
		log.Errorf("unable to marshal capture request. Error: %v", err)
		return
	}
	resp, errPost := req.Post(params.requestURI)
	hStatus := http.StatusServiceUnavailable
	if resp != nil {
		hStatus = resp.StatusCode()
	}
	if errPost != nil || hStatus != http.StatusAccepted {
		// resp could be nil here - in this case the next row will fall to panic()
		if errPost == nil {
			log.Errorf("improper status '%v' during node '%s' notification", hStatus, params.podAddr)
		} else {
			log.Errorf("error '%v' during node '%s' notification", errPost, params.podAddr)
		}
	}
}

// sedNotificationAsync
// notify known nodes about an event
func sedNotificationAsync(d *notifierImpl, req view.CaptureRequest, bStart bool) {
	nodeList, err := d.GetNodeList()
	if err != nil {
		log.Error(err)
		return
	}
	wg := sync.WaitGroup{}
	for _, v := range nodeList {
		if localAddress, bFound := d.locals[v]; bFound {
			log.Debugf("local node %s address %s skipped", localAddress, v)
			continue
		}
		log.Debugf("Notifying node %s", v)
		wg.Add(1)
		vn := entities.GossipStopPath
		if bStart {
			vn = entities.GossipStartPath
		}
		params := notificationParams{
			requestURI: fmt.Sprintf("%s%s:%d%s", d.EndPointProto, v, d.EndPointPort, vn),
			podAddr:    v,
		}
		utils.SafeAsync(func() {
			notifyNode(params, req, d.APIkey, &wg) // +SafeAsync
		})
	}
	wg.Wait()
	log.Println("all nodes notified")
}

// GetNodeList
// retrieves node list from kubernetes via kube_service
func (d *notifierImpl) GetNodeList() ([]string, error) {
	if d.ks != nil {
		ret := make([]string, 0) // most of the pod names will be discarded
		pl, err := d.ks.AcquireNamespacePodMap(d.KubeNameSpace)
		if err != nil {
			return nil, err
		}
		if len(pl) < 1 {
			return nil, errors.New("no namespace pods found")
		}
		for podIp, podName := range pl {
			log.Debugf("GetNodeList:POD %s->%s", podIp, podName)
			if localAddress, bFound := d.locals[podIp]; bFound {
				log.Debugf("local node %s address %s not added", localAddress, podIp)
				continue
			}
			nameIdx := strings.Index(podName, d.KubeNodeNamePrefix)
			if nameIdx == 0 || (nameIdx >= 1 && podName[nameIdx-1] == ' ') {
				ret = append(ret, podIp)
				log.Debugf("add node IP: %s", podIp)
			}
		}
		d.nodeList = ret
		return ret, nil
	}
	return nil, fmt.Errorf("kubernetes service is nil")
}

// interface implementation functions

// NotifyAll
// notifies neighbours nodes about new capture request asynchronously
func (d *notifierImpl) NotifyAll(req view.CaptureRequest, bStart bool) error {
	tn := time.Now()
	if d.unlockTime.Before(tn) {
		d.unlockTime = tn.Add(time.Second * 20)
		utils.SafeAsync(func() {
			sedNotificationAsync(d, req, bStart) // +SafeAsync
		})
	} else {
		log.Warnf("unable to notify too often. Please try again later (%s)", d.unlockTime.String())
	}
	return nil
}
func (d *notifierImpl) GetNamespaceList() ([]string, error) {
	if d.ks != nil {
		ret, err := d.ks.ListCloudNameSpaces()
		if err == nil {
			return ret, nil
		} else {
			return nil, err
		}
	}
	return nil, errors.New("kubernetes service is nil when looking for namespace list")
}
