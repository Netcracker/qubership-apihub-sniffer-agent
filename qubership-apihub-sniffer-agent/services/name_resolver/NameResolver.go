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

package name_resolver

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/cloud_storage"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/kube_service"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	log "github.com/sirupsen/logrus"
)

// NameResolver
// an external interface
type NameResolver interface {
	ResolveToName(capId string, ipAddr string)
	FlushNames(md entities.CaptureInstanceConfig)
}

// NameResolveRequest
// a request to name resolution
type NameResolveRequest struct {
	ipAddress string // address to resolve
	captureId string // capture Id to link
}

// NameRecord
// a cached record
type NameRecord struct {
	Name       string
	ResolvedAt int64
}

// captureAddrList
// in internal intermediate type
type captureAddrList map[string]int64

// nameResolverImpl
// an internal interface implementation
type nameResolverImpl struct {
	entities.KubernetesConfig
	queue           chan NameResolveRequest
	flushQueue      chan entities.CaptureInstanceConfig
	addrMap         map[string]string
	captureMap      map[string]captureAddrList
	serviceListLock sync.Mutex
	services        map[string]string
	servicesTime    time.Time
	s3              cloud_storage.CloudStorage
	ks              kube_service.K8Service
	instanceId      string
}

// listenResolverQueue
// goroutine to serve name resolution requests
func listenResolverQueue(instance *nameResolverImpl) {
	for {
		var req NameResolveRequest
		select {
		case req = <-instance.queue: // read request from channel
		case <-time.After(time.Second * 30): // channel writing timeout
			req.ipAddress = view.EmptyString
		}
		if req.ipAddress == view.EmptyString || req.captureId == view.EmptyString {
			continue // skip empty request
		}
		// while address being resolved - add it into capture map list
		capIpMap, capFound := instance.captureMap[req.captureId]
		if !capFound {
			capIpMap = make(captureAddrList, 1)
			capIpMap[req.ipAddress] = time.Now().Unix()
		} else {
			capIpMap[req.ipAddress] = time.Now().Unix()
		}
		instance.captureMap[req.captureId] = capIpMap // update capture address list
	}
}

// flushCaptureAddrList
// goroutine to serve address list flush for the particular capture ID
func flushCaptureAddrList(instance *nameResolverImpl) {
	for {
		req := <-instance.flushQueue // read request from channel
		if req.Id == view.EmptyString {
			continue
		}
		if len(req.Namespaces) > 0 {
			for _, namespaceName := range req.Namespaces {
				_, err := instance.ks.AcquireNamespaceAddresses(namespaceName)
				if err != nil {
					log.Errorf("unable to acquire addresses for namespace %s: %v", namespaceName, err)
				}
			}
		}
		capAddresses, found := instance.captureMap[req.Id]
		if found {
			// address list found - resolve addresses
			resolvedCount := 0
			for i := 0; i < 2; i++ {
				for iip := range capAddresses {
					rec, resolved := instance.addrMap[iip]
					if !resolved {
						rec = instance.ks.GetAddressServiceName(iip)
						instance.addrMap[iip] = rec
						resolvedCount++
					} else {
						if rec == view.EmptyString {
							rec = instance.ks.GetAddressServiceName(iip)
							instance.addrMap[iip] = rec
							resolvedCount++
						}
					}
				}
				if resolvedCount > 0 {
					break
				}
			}
			if resolvedCount != len(capAddresses) {
				log.Debugf("not all addreses (%d of %d) resolved for capture: %s. writing incomplete file",
					resolvedCount, len(capAddresses), req.Id)
			}
			if instance.s3 != nil {
				// all items resolved - write them to file
				ofn := fmt.Sprintf("%s_%s_address_list.txt", req.Id, instance.instanceId)
				of, err := os.Create(ofn)
				if err != nil {
					log.Errorf("request for capture dropper due to issue with opening '%s' for writing. Error: %v", ofn, err)
					return
				}
				for iip, item := range capAddresses {

					_, err := of.WriteString(fmt.Sprintf("%s\t%s\n", iip, instance.addrMap[iip]))
					if err != nil {
						log.Errorf("unable to write IP %s with timestamp %s into file '%s'. Error: %v", iip, time.Unix(item, 0).String(), ofn, err)
					}
				}
				// close the address list file
				err = of.Close()
				if err != nil {
					log.Warnf("unable to close address list file. Error: %v", err)
				}
				// file has been written - send it to S3/Minio storage
				instance.s3.StoreFile(ofn)
			} else {
				log.Warnf("no s3/Minio initialized - discard creating address list file for capture: %s", req.Id)
			}
		} else {
			log.Errorf("no data found for capture %s", req.Id)
		}
	}
}

// NewNameResolver
// initialize an interface implementation
func NewNameResolver(config entities.KubernetesConfig, cs cloud_storage.CloudStorage, ks kube_service.K8Service, instanceId string) NameResolver {
	ret := &nameResolverImpl{
		KubernetesConfig: config,
		queue:            make(chan NameResolveRequest),
		flushQueue:       make(chan entities.CaptureInstanceConfig),
		addrMap:          make(map[string]string),
		captureMap:       make(map[string]captureAddrList),
		services:         nil,
		servicesTime:     time.Now(),
		s3:               cs,
		ks:               ks,
		instanceId:       instanceId,
	}
	// name resolve queue
	utils.SafeAsync(func() {
		listenResolverQueue(ret)
	})
	// capture flush queue
	utils.SafeAsync(func() {
		flushCaptureAddrList(ret)
	})
	return ret
}

// ResolveToName
// push name resolution request to queue
func (nr *nameResolverImpl) ResolveToName(capId string, ipAddr string) {
	nr.queue <- NameResolveRequest{ipAddress: ipAddr, captureId: capId}
}

// FlushNames
// push address list flush request to queue
func (nr *nameResolverImpl) FlushNames(md entities.CaptureInstanceConfig) {
	nr.flushQueue <- md
}
