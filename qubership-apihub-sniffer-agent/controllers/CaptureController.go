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

package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/exception"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/capture"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/neighbour"
	log "github.com/sirupsen/logrus"
)

// TODO: status report (far future)

// Service
// an interface to controller
type Service interface {
	OnStart(w http.ResponseWriter, r *http.Request)
	OnStop(w http.ResponseWriter, r *http.Request)
	OnInterfaces(w http.ResponseWriter, r *http.Request)
	OnAddressMap(w http.ResponseWriter, r *http.Request)
	OnNeighbours(w http.ResponseWriter, r *http.Request)
	OnNamespaces(w http.ResponseWriter, r *http.Request)
	OnStatus(w http.ResponseWriter, r *http.Request)
	OnCaptureStatus(w http.ResponseWriter, r *http.Request)
	Close()
}

type webService struct {
	entities.CaptureControllerConfig
	pkt        capture.Capture // local capture service
	captures   map[string]entities.CaptureInstanceConfig
	chCap      chan string
	neighbours neighbour.NotificationSender // neighbour discovery service
}

// constants
const (
	//requestValidationFailed   = "Request did not pass the internal validation"
	requestNotificationFailed = "unable to send %s notify to nodes. Error: %v"
	notificationNotSent       = "no %s notification will send"
	requestBodyDeferError     = "unable to defer request body. error: %v"
	HttpContentType           = "Content-Type"
	invalidApiKey             = "API key not match"
	emptyApiKey               = "empty API key not allowed in production mode"
	emptyCaptureId            = "Capture Id is empty"
	checkSumNotMatch          = "checksum value not match"
	startCapture              = "start"
	stopCapture               = "stop"
)

// NewWebService
// creates a new web interface instance
func NewWebService(pkt capture.Capture, neighbours neighbour.NotificationSender, config entities.CaptureControllerConfig) Service {
	ws := &webService{
		CaptureControllerConfig: config,
		pkt:                     pkt,        // packet capture
		neighbours:              neighbours, // neighbour notifier (could be nil)
		captures:                make(map[string]entities.CaptureInstanceConfig),
		chCap:                   make(chan string),
	}
	utils.SafeAsync(func() {
		for {
			rs := <-ws.chCap
			if rs == view.EmptyString {
				log.Info("webservice capture status channel completed")
				break
			}
			_, found := ws.captures[rs]
			if !found {
				log.Warnf("webservice: no capture found for %s", rs)
			} else {
				delete(ws.captures, rs)
			}
		}
	})
	return ws
}

func RespondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set(HttpContentType, "application/json")
	w.WriteHeader(code)
	write, err := w.Write(response)
	if err != nil {
		log.Debugf("%d response bytes written with error: %v", write, err)
	}
}
func RespondWithCustomError(w http.ResponseWriter, err *exception.CustomError) {
	log.Debugf("Request failed. Code = %d. Message = %s. Params: %v. Debug: %s", err.Status, err.Message, err.Params, err.Debug)
	RespondWithJson(w, err.Status, err)
}

// OnStart
// try to start packet capture (external interface to receive user requests)
func (ws *webService) OnStart(w http.ResponseWriter, r *http.Request) {
	body, err := ws.checkAndGetBody(w, r)
	if err != nil {
		return
	}
	var rb view.CaptureRequest
	err = json.Unmarshal(body, &rb)
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.BadRequestBody,
			Message: exception.BadRequestBodyMsg,
			Debug:   err.Error(),
		})
		return
	}
	rib, err := entities.MakeCaptureInstanceConfig(rb, ws.APIkey, ws.InternalKey)
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.BadRequestBody,
			Message: exception.BadRequestBodyMsg,
			Debug:   err.Error(),
		})
		return
	}
	if rib.Duration < view.MinCaptureDuration {
		log.Warnf("too short duration (%v) passed. falling back to default (%s)", rib.Duration, view.DefaultCaptureDuration.String())
		rib.Duration = view.DefaultCaptureDuration
	}
	if rib.FileSize < 1 {
		log.Warnf("improper file size (%d) passed. falling back to default (%d)", rib.FileSize, view.DefaultFileDataSize)
		rib.FileSize = view.DefaultFileDataSize
	}
	if rib.SnapshotLen <= 0 {
		rib.SnapshotLen = view.DefaultSnapLenBytes
		log.Warnf("improper capture snapshot length requested. dafaulting to %d bytes", rib.SnapshotLen)
	}
	switch rib.Status {
	case entities.VrGossipValidated:
		{
			// checksum validated - gossip received
			// just start capture
			break
		}
	case entities.VrCheckSumNotMatch:
		{ // computed value does not equal to received
			RespondWithCustomError(w, &exception.CustomError{
				Status:  http.StatusBadRequest,
				Code:    exception.RequiredParamsMissing,
				Message: exception.RequiredParamsMissingMsg,
				Debug:   checkSumNotMatch,
			})
			return
		}
	case entities.VrCheckSumEmpty, entities.VrDateTimeEmpty, entities.VrIdEmpty:
		{ // client request
			// make capture Id
			rib.Id = utils.MakeUniqueId()
			// set timestamp
			rib.DateAndTime = time.Now()
			// convert entity to view
			rb = entities.ConvertToCaptureRequest(rib, ws.APIkey, ws.InternalKey)
			// convert view structure to []byte
			metaData, err := json.Marshal(rb)
			if err != nil {
				log.Errorf("unable to marshal capture request for metadata. Error: %v", err)
				return
			} else {
				// save metadata file and pass it to S3/Minio
				err = ws.pkt.SaveCaptureMedata(rb.Id+"_metadata.json", metaData)
				if err != nil {
					log.Errorf("unable to save capture request metadata. Error: %v", err)
				}
			}
			if ws.neighbours != nil {
				log.Debugf("client %s request - spread gossip", startCapture)
				//spread gossip
				err = ws.neighbours.NotifyAll(rb, true)
				if err != nil {
					log.Errorf(requestNotificationFailed, startCapture, err)
				}
			} else {
				log.Debugf(notificationNotSent, startCapture)
			}
		}
	default:
		{
			log.Debugf("default case for %d", rib.Status)
			break
		}
	}
	if len(ws.captures) > 0 {
		for ck := range ws.captures {
			if entities.CaptureConfigurationEqual(ws.captures[ck], rib) {
				log.Warnf("the same configuration is running under id %s", ck)
			}
		}
	}
	err = ws.pkt.StartCapture(rib, ws.chCap)
	if err == nil {
		result := ws.pkt.GetStatus()
		if result.Status != view.RequestStatusRunning && result.Status != view.RequestStatusStarting {
			RespondWithJson(w, http.StatusInternalServerError, result)
		} else {
			RespondWithJson(w, http.StatusAccepted, result)
			ws.captures[rib.Id] = rib
		}
		return
	}
	RespondWithCustomError(w, &exception.CustomError{
		Status:  http.StatusServiceUnavailable,
		Code:    exception.UnableToStartCapture,
		Message: exception.UnableToStartCaptureMsg,
		Debug:   err.Error(),
	})
}

// OnStop
// try to stop packet capture
func (ws *webService) OnStop(w http.ResponseWriter, r *http.Request) {
	body, err := ws.checkAndGetBody(w, r)
	if err != nil {
		return
	}
	var rb view.CaptureRequest
	err = json.Unmarshal(body, &rb)
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.BadRequestBody,
			Message: exception.BadRequestBodyMsg,
			Debug:   err.Error(),
		})
		return
	}
	rib, err := entities.MakeCaptureInstanceConfig(rb, ws.APIkey, ws.InternalKey)
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.BadRequestBody,
			Message: exception.BadRequestBodyMsg,
			Debug:   err.Error(),
		})
		return
	}
	switch rib.Status {
	case entities.VrGossipValidated:
		{
			// checksum validated - gossip received
			// just start capture
			break
		}
	case entities.VrIdEmpty:
		{ // capture ID must not be empty
			RespondWithCustomError(w, &exception.CustomError{
				Status:  http.StatusBadRequest,
				Code:    exception.RequiredParamsMissing,
				Message: exception.RequiredParamsMissingMsg,
				Debug:   emptyCaptureId,
			})
			return
		}
	case entities.VrCheckSumNotMatch:
		{ // computed value does not equal to received
			RespondWithCustomError(w, &exception.CustomError{
				Status:  http.StatusBadRequest,
				Code:    exception.RequiredParamsMissing,
				Message: exception.RequiredParamsMissingMsg,
				Debug:   checkSumNotMatch,
			})
			return
		}
	case entities.VrCheckSumEmpty, entities.VrDateTimeEmpty:
		{
			if ws.neighbours != nil {
				// client request - spread gossip
				rib.DateAndTime = time.Now()
				rb = entities.ConvertToCaptureRequest(rib, ws.APIkey, ws.InternalKey)
				log.Debugf("client %s request - spread gossip", stopCapture)
				err = ws.neighbours.NotifyAll(rb, false)
				if err != nil {
					log.Errorf(requestNotificationFailed, stopCapture, err)
				}
			} else {
				log.Debugf(notificationNotSent, stopCapture)
			}
		}
	default:
		{
			log.Debugf("default case for %d", rib.Status)
			break
		}
	}
	result, err := ws.pkt.StopCapture(rb.Id)
	if err == nil {
		switch result.Status {
		case view.RequestStatusNone: // no capture to stop
			RespondWithJson(w, http.StatusNotFound, result)
		case view.RequestStatusStopping, view.RequestStatusStopped, view.RequestStatusCompleted:
			RespondWithJson(w, http.StatusAccepted, result) // good result
		default:
			RespondWithJson(w, http.StatusInternalServerError, result) // bad result
		}
		return
	}
	RespondWithCustomError(w, &exception.CustomError{
		Status:  http.StatusServiceUnavailable,
		Code:    exception.UnableToStopCapture,
		Message: exception.UnableToStopCaptureMsg,
		Debug:   err.Error(),
	})
}

// OnInterfaces
// returns list of network interface names or reports error
func (ws *webService) OnInterfaces(w http.ResponseWriter, r *http.Request) {
	_, err := ws.checkAndGetBody(w, r)
	if err != nil {
		return
	}
	interfaces, err := capture.LocalInterfaces(true)
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusServiceUnavailable,
			Code:    exception.UnableToListInterfaces,
			Message: exception.UnableToListInterfacesMsg,
			Debug:   err.Error(),
		})
		return
	}
	RespondWithJson(w, http.StatusOK, interfaces)
}

// OnAddressMap
// returns map of addresses assigned on network interfaces or reports error
func (ws *webService) OnAddressMap(w http.ResponseWriter, r *http.Request) {
	_, err := ws.checkAndGetBody(w, r)
	if err != nil {
		return
	}
	addressMap, err := capture.LocalAddrMap()
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusServiceUnavailable,
			Code:    exception.UnableToListAddresses,
			Message: exception.UnableToListAddressesMsg,
			Debug:   err.Error(),
		})
		return
	}
	RespondWithJson(w, http.StatusOK, addressMap)
}

func (ws *webService) OnNeighbours(w http.ResponseWriter, r *http.Request) {
	if ws.neighbours == nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusServiceUnavailable,
			Code:    exception.UnableToListAddresses,
			Message: exception.UnableToListAddressesMsg,
			Debug:   "no neighbours service initialized",
		})
		return
	}
	_, err := ws.checkAndGetBody(w, r)
	if err == nil {
		var nodes []string
		nodes, err = ws.neighbours.GetNodeList()
		if err == nil {
			RespondWithJson(w, http.StatusOK, nodes)
			return
		}
	}
	RespondWithCustomError(w, &exception.CustomError{
		Status:  http.StatusServiceUnavailable,
		Code:    exception.UnableToListAddresses,
		Message: exception.UnableToListAddressesMsg,
		Debug:   err.Error(),
	})
}

func (ws *webService) OnNamespaces(w http.ResponseWriter, r *http.Request) {
	if ws.neighbours == nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusServiceUnavailable,
			Code:    exception.UnableToListAddresses,
			Message: exception.UnableToListAddressesMsg,
			Debug:   "no neighbours service initialized",
		})
		return
	}
	_, err := ws.checkAndGetBody(w, r)
	if err == nil {
		var nodes []string
		nodes, err = ws.neighbours.GetNamespaceList()
		if err == nil {
			RespondWithJson(w, http.StatusOK, nodes)
			return
		}
	}
	RespondWithCustomError(w, &exception.CustomError{
		Status:  http.StatusServiceUnavailable,
		Code:    exception.UnableToListAddresses,
		Message: exception.UnableToListAddressesMsg,
		Debug:   err.Error(),
	})
}

func (ws *webService) OnCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if ws.neighbours == nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusServiceUnavailable,
			Code:    exception.UnableToListAddresses,
			Message: exception.UnableToListAddressesMsg,
			Debug:   "no neighbours service initialized",
		})
		return
	}
	_, err := ws.checkAndGetBody(w, r)
	if err == nil {
		RespondWithJson(w, http.StatusOK, ws.pkt.GetStatus())
		return
	}
	RespondWithCustomError(w, &exception.CustomError{
		Status:  http.StatusServiceUnavailable,
		Code:    exception.UnableToListAddresses,
		Message: exception.UnableToListAddressesMsg,
		Debug:   err.Error(),
	})
}

// OnStatus
// reports status on TTL requests
func (ws *webService) OnStatus(w http.ResponseWriter, _ *http.Request) {
	RespondWithJson(w, http.StatusOK, "") // always respond OK to calm the watchdogs
}

func (ws *webService) Close() {
	select {
	case ws.chCap <- view.EmptyString:
		break // command accepted
	case <-time.After(time.Second * 5):
		log.Warnf("wsebservice: timeout sending stop command") // channel writing timeout - force to stop anyhow
	}
}

// checkAndGetBody
// checks API key and reads body contents
func (ws *webService) checkAndGetBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if ws.APIkey != view.EmptyString {
		apiKeyHeader := r.Header.Get(view.ApiKeyHeader)
		if apiKeyHeader != ws.APIkey {
			RespondWithCustomError(w, &exception.CustomError{
				Status:  http.StatusUnauthorized,
				Code:    exception.ApiKeyNotFound,
				Message: exception.ApiKeyNotFoundMsg,
				Debug:   invalidApiKey,
			})
			return nil, fmt.Errorf(invalidApiKey)
		}
	} else {
		if ws.ProductionMode {
			RespondWithCustomError(w, &exception.CustomError{
				Status:  http.StatusUnauthorized,
				Code:    exception.EmptyParameter,
				Message: exception.EmptyParameterMsg,
				Debug:   emptyApiKey,
			})
			return nil, fmt.Errorf(emptyApiKey)
		}
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Debugf(requestBodyDeferError, err)
		}
	}(r.Body)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespondWithCustomError(w, &exception.CustomError{
			Status:  http.StatusBadRequest,
			Code:    exception.BadRequestBody,
			Message: exception.BadRequestBodyMsg,
			Debug:   err.Error(),
		})
		return nil, err
	}
	return body, nil
}
