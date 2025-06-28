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

package exception

const EmptyParameter = "8"
const EmptyParameterMsg = "Parameter $param should not be empty"

const BadRequestBody = "10"
const BadRequestBodyMsg = "Failed to decode body"

const RequiredParamsMissing = "15"
const RequiredParamsMissingMsg = "Required parameters are missing: $params"

const ApiKeyNotFound = "83"
const ApiKeyNotFoundMsg = "Api key for user $user and integration $integration not found"

// UnableToStartCapture capture codes and messages
const UnableToStartCapture = "20000"
const UnableToStartCaptureMsg = "unable to start capture"
const UnableToStopCapture = "20001"
const UnableToStopCaptureMsg = "unable to stop capture"
const UnableToListInterfaces = "20002"
const UnableToListInterfacesMsg = "unable to list network interfaces"
const UnableToListAddresses = "20003"
const UnableToListAddressesMsg = "unable to get local address list"
