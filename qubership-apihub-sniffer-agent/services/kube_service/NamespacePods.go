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
	"context"
	"fmt"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	v6entity "github.com/netcracker/qubership-core-lib-go-paas-mediation-client/v8/entity"
	v6filter "github.com/netcracker/qubership-core-lib-go-paas-mediation-client/v8/filter"
	paasService "github.com/netcracker/qubership-core-lib-go-paas-mediation-client/v8/service"
)

type PodsRet struct {
	Pods  []v6entity.Pod
	Error error
}

// listNamespacePods
// list the namespace PODs with panic protection
func listNamespacePods(clientSet paasService.PlatformService, nsName string, ctx context.Context) ([]v6entity.Pod, error) {
	var podsRet PodsRet
	errChannel := make(chan PodsRet)
	utils.SafeAsync(func() {
		var pods PodsRet
		// the row below could cause panic
		pods.Pods, pods.Error = clientSet.GetPodList(ctx, nsName, v6filter.Meta{})
		errChannel <- pods
	})
	select {
	case podsRet = <-errChannel:
		break
	case <-time.After(time.Minute):
		podsRet.Error = fmt.Errorf("timeout getting POD list for namespace: %s", nsName)
	}
	return podsRet.Pods, podsRet.Error
}

// filterPodsWithSelector
// filter PODs by service selector
func filterPodsWithSelector(allPods []v6entity.Pod, selector map[string]string) []v6entity.Pod {
	result := make([]v6entity.Pod, 0)
	if len(selector) == 0 {
		return result
	}
	for _, pod := range allPods {
		matchSelectors := 0
		for k, v := range selector {
			if pod.Labels[k] == v {
				matchSelectors++
			}
		}
		if matchSelectors == len(selector) {
			result = append(result, pod)
		}
	}
	return result
}
