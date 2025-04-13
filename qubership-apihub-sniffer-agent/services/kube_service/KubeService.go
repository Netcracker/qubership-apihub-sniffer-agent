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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/disk_cache"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/akrylysov/pogreb"
	v6filter "github.com/netcracker/qubership-core-lib-go-paas-mediation-client/v8/filter"
	paasService "github.com/netcracker/qubership-core-lib-go-paas-mediation-client/v8/service"
	log "github.com/sirupsen/logrus"
)

// internal constants

const (
	// clientSetIsNil common error text
	clientSetIsNil      = "kubernetes client set has not been initialized yet"
	InterfaceConversion = "interface conversion error for parameter"
	// namespacePodsTTl
	// renew time for namespace POD list (it takes more than a minute to acquire data from kubernetes cloud)
	namespacePodsTTl   = time.Second * 5
	LongServiceTimeout = time.Second * 30
)

// internal types
// kubeServices a map of service names by their addresses
//type kubeServices struct {
//	entities.CachedItem                      // update lock and last update time
//	pods                disk_cache.DiskCache // IP to POD map
//	services            disk_cache.DiskCache // POD to service map
//}

// kubePods a cached namespace pods
type kubePods struct {
	entities.CachedItem                         // update lock and last update time
	namespacePods       map[string]NamespaceRow // pods by namespace name
}

// kubeServiceImpl a kubernetes service implementation
type kubeServiceImpl struct {
	// config kubernetes access configuration
	config entities.KubernetesConfig
	// namespacePods namespaces' pods
	namespacePods kubePods
	// pods IP to POD map
	pods disk_cache.DiskCache
	// services POD to service map
	diskCacheUpdateTime time.Time
	// clientSet kubernetes interface
	clientSet paasService.PlatformService
	// clientSetBusy - to lock multiple client set updates
	clientSetBusy sync.Mutex
}

// public types

// NamespaceRow
// a namespace cache row
type NamespaceRow struct {
	LastUpdated time.Time
	Pods        map[string]string
}

type StringArrayRet struct {
	StringArray []string
	Error       error
}

type StringMapRet struct {
	stringMap map[string]string
	err       error
}

type AsyncParamArrayRet struct {
	Result chan StringArrayRet
	Param  interface{}
}

type AsyncParamMapRet struct {
	res   chan StringMapRet
	param interface{}
}

type ParamArrayRet struct {
	StringArray []string
	Error       error
	param       interface{}
}

type ParamMapRet struct {
	stringMap map[string]string
	err       error
	param     interface{}
}

// K8Service
// public interface
type K8Service interface {
	GetAddressServiceName(ipAddress string) string
	AcquireNamespacePodMap(nsName string) (map[string]string, error)
	DumpAddressMap(fileName string) error
	AcquireNamespaceAddresses(nsName string) ([]string, error)
	ListCloudNameSpaces() ([]string, error)
}

// private methods

// acquireClientSet
// acquire client set asynchronously, try to catch panic
func (ks *kubeServiceImpl) acquireClientSet(kubeconfig entities.KubernetesConfig) {
	ks.clientSetBusy.Lock()
	defer ks.clientSetBusy.Unlock()
	clientSet, err := paasService.NewPlatformClientBuilder().WithNamespace(kubeconfig.KubeNameSpace).Build()
	if err != nil {
		log.Errorf("unable to acquire client set: %v", err)
	} else {
		ks.clientSet = clientSet
	}
}

// Public interface method implementation

// NewKubeService
// initialises a public interface
func NewKubeService(cfg *entities.KubernetesConfig, podCache disk_cache.DiskCache) (K8Service, error) {
	ret := &kubeServiceImpl{
		config: *cfg,
		namespacePods: kubePods{
			CachedItem: entities.CachedItem{
				LastUpdateTime: time.Time{},
				UpdateLock:     sync.Mutex{},
			},
			namespacePods: make(map[string]NamespaceRow),
		},
		pods:          podCache,
		clientSet:     nil,
		clientSetBusy: sync.Mutex{},
	}
	ret.acquireClientSet(*cfg)
	return ret, nil
}

// GetAddressServiceName
// get service name by its IP address
func (ks *kubeServiceImpl) GetAddressServiceName(ipAddress string) string {
	runParam := ParamArrayRet{
		param:       ks,
		StringArray: make([]string, 1),
	}
	utils.SafeRunWithParam(func(param interface{}) {
		inputParam := param.(*ParamArrayRet)
		ks, converted := inputParam.param.(*kubeServiceImpl)
		if !converted {
			inputParam.Error = fmt.Errorf(InterfaceConversion)
			//inputParam.StringArray[0] = view.EmptyString
			return
		}
		curTime := time.Now()
		bNeedUpdate := false
		if ks.pods == nil {
			bNeedUpdate = true
			log.Debugf("new service data")
			//inputParam.StringArray[0] = view.EmptyString
			return
		} else {
			if curTime.After(ks.diskCacheUpdateTime) {
				bNeedUpdate = true
				log.Debugf("service cache update due to overtime %s", curTime.Sub(ks.diskCacheUpdateTime).String())
			}
		}
		if bNeedUpdate {
			nsList, err := ks.listCloudNameSpaces()
			if err == nil && len(nsList) > 0 {
				for _, ns := range nsList {
					err := ks.listNameSpaceServices(ns)
					if err != nil {
						log.Warnf("Error %v acquiring namespace '%s'", err, ns)
					}
				}
			} else {
				if err != nil {
					log.Warnf("Error acquiring namespaces %v. Working with '%s' only ", err, ks.config.KubeNameSpace)
				} else {
					log.Warnf("no namespace acquired. Working with '%s' only ", ks.config.KubeNameSpace)
				}
				err = ks.listNameSpaceServices(ks.config.KubeNameSpace)
				if err != nil {
					log.Warnf("Error acquiring service map %v", err)
				}
			}
			ks.diskCacheUpdateTime = time.Now().Add(namespacePodsTTl)
		}
		cloudSvc, ipLookupError := ks.pods.GetItem(ipAddress)
		if ipLookupError != nil {
			log.Warnf("IP address %s not in cache %v", ipAddress, ipLookupError)
			//inputParam.StringArray[0] = view.EmptyString
			return
		}
		if len(cloudSvc) > 0 {
			var svc entities.CloudService
			decodeErr := entities.UnmarshallCloudService(&svc, cloudSvc)
			if decodeErr != nil {
				log.Errorf("unable to unmarshall cloud service for IP %s: %v (%s)", ipAddress, decodeErr, string(cloudSvc))
			} else {
				runParam.StringArray[0] = svc.Name
			}
		} else {
			log.Debugf("empty value for IP address %s", ipAddress)
		}
	}, &runParam)
	return runParam.StringArray[0]
}

// AcquireNamespacePodMap
// list all PODs in the namespace, returns map 'POD IP'->'POD name'
func (ks *kubeServiceImpl) AcquireNamespacePodMap(nsName string) (map[string]string, error) {
	pods, err := ks.clientSet.GetPodList(goctx.Background(), nsName, v6filter.Meta{})
	if err != nil {
		return nil, fmt.Errorf("unable to acquire namespace '%s' PODs, error: %v", err, nsName)
	}
	if pods == nil {
		return nil, fmt.Errorf("PODs list is nil for namespace %s", nsName)
	}
	ret := make(map[string]string)
	for _, pod := range pods {
		name, found := ret[pod.Status.PodIP]
		if !found {
			ret[pod.Status.PodIP] = pod.Name
		} else {
			if !strings.Contains(name, pod.Name) {
				ret[pod.Status.PodIP] = fmt.Sprintf("%s, %s", name, pod.Name)
			}
		}
		// don't touch pod.Status.HostIP - this is a node IP
	}
	return ret, nil
}

// DumpAddressMap
// debug method to print address map contents
func (ks *kubeServiceImpl) DumpAddressMap(fileName string) error {
	fh, err := os.Create(fileName)
	if err != nil {
		log.Errorf("Error creating file %s for dumping address map", fileName)
		return err
	}
	defer func(fh *os.File) {
		err := fh.Close()
		if err != nil {
			log.Errorf("unable to close file %s for dumping address map", fileName)
		}
	}(fh)
	itr, err := ks.pods.Iterate()
	for {
		ip, bSvrEnt, errIterate := ks.pods.IterateItemBytes(itr)
		if errIterate != nil {
			if !errors.Is(errIterate, ks.pods.NilIteratorError()) && !errors.Is(err, pogreb.ErrIterationDone) {
				err = errIterate
			}
			break
		}
		var svrEnt entities.CloudService
		err = entities.UnmarshallCloudService(&svrEnt, bSvrEnt)
		if err != nil {
			break
		}
		_, writeErr := fh.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\n", ip, svrEnt.Name, svrEnt.Version, svrEnt.NameSpace))
		if writeErr != nil {
			err = writeErr
			break
		}
	}
	return err
}

// AcquireNamespaceAddresses
// returns namespace's IP addresses
func (ks *kubeServiceImpl) AcquireNamespaceAddresses(nsName string) ([]string, error) {
	paramToRun := AsyncParamArrayRet{
		Param:  ks,
		Result: make(chan StringArrayRet),
	}
	utils.SafeAsyncWithParam(func(param interface{}) {
		inputParam := param.(AsyncParamArrayRet)
		ks, converted := inputParam.Param.(*kubeServiceImpl)
		if !converted {
			inputParam.Result <- StringArrayRet{Error: fmt.Errorf(InterfaceConversion)}
			return
		}
		//ks.clientSetBusy.Lock()
		//defer ks.clientSetBusy.Unlock()
		err := ks.listNameSpaceServices(nsName)
		if err != nil {
			log.Debugf("Error %v acquiring namespace '%s'", err, nsName)
		}
		if ks.pods == nil {
			inputParam.Result <- StringArrayRet{Error: fmt.Errorf("service PODs is still nil")}
			return
		}
		iti, err := ks.pods.Iterate()
		if err != nil {
			if !errors.Is(err, ks.pods.NilIteratorError()) && !errors.Is(err, pogreb.ErrIterationDone) {
				log.Debugf("unable to iterate IPs for namespace %s : %v", nsName, err)
				inputParam.Result <- StringArrayRet{Error: err}
			} else {
				log.Warnf("NilIteratorError while looking for namespace %s pods: %v", nsName, err)
				inputParam.Result <- StringArrayRet{Error: nil}
			}
			return
		}
		ret := StringArrayRet{StringArray: make([]string, 0), Error: nil}
		var svrEnt entities.CloudService
		for iti != nil {
			key, val, iteratorErr := ks.pods.IterateItemBytes(iti)
			if iteratorErr != nil {
				if !errors.Is(iteratorErr, ks.pods.NilIteratorError()) && !errors.Is(iteratorErr, pogreb.ErrIterationDone) {
					err = fmt.Errorf("unable to iterate IP : %v", iteratorErr)
				}
				break
			}
			log.Debugf("AcquireNamespaceAddresses key:%s val:%v", key, val)
			err = entities.UnmarshallCloudService(&svrEnt, val)
			if err == nil {
				if svrEnt.NameSpace == nsName {
					ret.StringArray = append(ret.StringArray, key)
				}
			} else {
				err = fmt.Errorf("unable to parse %s: %v", string(val), err)
			}
		}
		ret.Error = err
		inputParam.Result <- ret
	}, paramToRun)
	ret := <-paramToRun.Result
	log.Debugf("Acquired Namespace Addresses for namespace %s result: %d:%v", nsName, len(ret.StringArray), ret.Error)
	return ret.StringArray, ret.Error
}

// ListCloudNameSpaces
// returns cloud namespace list
func (ks *kubeServiceImpl) ListCloudNameSpaces() ([]string, error) {
	runParam := AsyncParamArrayRet{
		Param:  ks,
		Result: make(chan StringArrayRet),
	}
	utils.SafeAsyncWithParam(func(param interface{}) {
		inputParam := param.(AsyncParamArrayRet)
		ks, converted := inputParam.Param.(*kubeServiceImpl)
		var ret StringArrayRet
		if !converted {
			ret.Error = errors.New(InterfaceConversion)
		} else {
			ret.StringArray, ret.Error = ks.listCloudNameSpaces()
		}
		inputParam.Result <- ret
	}, runParam)
	ret := <-runParam.Result
	return ret.StringArray, ret.Error
}
