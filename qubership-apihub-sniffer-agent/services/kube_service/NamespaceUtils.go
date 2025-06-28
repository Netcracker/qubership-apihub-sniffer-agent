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

package kube_service

import (
	goctx "context"
	"encoding/json"
	"fmt"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	v6filter "github.com/netcracker/qubership-core-lib-go-paas-mediation-client/v8/filter"
	log "github.com/sirupsen/logrus"
)

// addPodToMap
// adds CloudService info to map
func addPodToMap(pods map[string]entities.CloudService, ipAddress string, cloudService entities.CloudService) {
	if ipAddress != "None" && ipAddress != view.EmptyString &&
		(cloudService.Name != view.EmptyString || cloudService.PodName != view.EmptyString) {
		pods[ipAddress] = cloudService
	}
}

// listNameSpaceServices
// returns a fresh (initialize and update as needed)  service names to IPs map (unprotected, private)
func (ks *kubeServiceImpl) listNameSpaceServices(nsName string) error {
	if ks.clientSet == nil {
		return fmt.Errorf(clientSetIsNil)
	}
	ctx := goctx.Background()
	// get all the service names in the namespace
	pods, err := ks.clientSet.GetPodList(ctx, nsName, v6filter.Meta{})
	if err != nil {
		log.Debugf("unable to get pod list for namespace %s. Error: %v", nsName, err)
	} else {
		podMap := make(map[string]entities.CloudService)
		for _, pod := range pods {
			addPodToMap(podMap, pod.Status.PodIP, entities.CloudService{PodName: pod.Name, Name: pod.Name, NameSpace: nsName})
		}
		// the commented code below consume a lot of time and resources
		services, svcErr := ks.clientSet.GetServiceList(ctx, nsName, v6filter.Meta{})
		if svcErr != nil {
			log.Debugf("unable to get services for the namespace %s. Error: %v", svcErr, nsName)
		} else {
			log.Debugf("found %d services for the namespace %s", len(services), nsName)
			log.Debugf("found %d (%d) PODs for the namespace %s", len(pods), ks.pods.Count(), nsName)
		}
		for _, srv := range services {
			svrEnt := entities.CloudService{
				Name:      srv.Name,
				NameSpace: nsName,
			}
			if svrEnt.Name == view.EmptyString {
				continue
			}
			svrEnt.Version = srv.Labels[entities.ServiceVersionLabel]
			servicePods := filterPodsWithSelector(pods, srv.Spec.Selector)
			for _, pod := range servicePods {
				if pod.Name != view.EmptyString {
					svrEnt.PodName = pod.Name
					addPodToMap(podMap, pod.Status.PodIP, svrEnt)
				}
			}
		}
		// flush map to cache
		for ipAddress, svc := range podMap {
			bytea, errMarshal := json.Marshal(svc)
			if errMarshal != nil {
				return fmt.Errorf("unable to marshal service for namespace %s. Error: %v", nsName, errMarshal)
			}
			errStore := ks.pods.StoreItem(ipAddress, string(bytea))
			if errStore != nil {
				return fmt.Errorf("unable to store service %s. Error: %v", svc.Name, errStore)
			}
		}
	}
	return nil
}

// listCloudNameSpaces
// list all namespace names in the cloud (unprotected, private)
func (ks *kubeServiceImpl) listCloudNameSpaces() ([]string, error) {
	ret := make([]string, 0)
	if ks.clientSet == nil {
		return ret, fmt.Errorf(clientSetIsNil)
	}
	nameSpaces, err := ks.clientSet.GetNamespaces(goctx.Background(), v6filter.Meta{})
	if err == nil {
		for _, nameSpace := range nameSpaces {
			if nameSpace.Name != view.EmptyString {
				ret = append(ret, nameSpace.Name)
			}
		}
		return ret, nil
	}
	return ret, err
}
