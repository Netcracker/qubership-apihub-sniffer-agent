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

package service

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/capture"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	log "github.com/sirupsen/logrus"
)

const (
	ListenAddress           = "LISTEN_ADDRESS"
	OriginAllowed           = "ORIGIN_ALLOWED"
	KubeNameSpace           = "NAMESPACE"
	MinioAccessKeyId        = "STORAGE_SERVER_USERNAME"
	MinioSecretAccessKey    = "STORAGE_SERVER_PASSWORD"
	MinioCrt                = "STORAGE_SERVER_CRT"
	MinioEndpoint           = "STORAGE_SERVER_URL"
	MinioBucketName         = "STORAGE_SERVER_BUCKET_NAME"
	MinioStorageActive      = "MINIO_STORAGE_ACTIVE"
	CaptureInterface        = "CAPTURE_INTERFACE"
	CaptureDirectory        = "CAPTURE_DIRECTORY"
	CaptureSnapLen          = "CAPTURE_SNAPSHOT_LEN"
	CaptureFileCompression  = "CAPTURE_FILE_COMPRESSION"
	KubeConfig              = "KUBECONFIG"
	KubeSecurityContext     = "KUBE_CONTEXT"
	KubeNodeNamePrefix      = "KUBE_NODE_PREFIX"
	APIkey                  = "SNIFFER_API_KEY"
	InternalKey             = "SNIFFER_INTERNAL_KEY"
	ProductionMode          = "PRODUCTION_MODE"
	EndPointProto           = "ENDPOINT_PROTOCOL" // http:// or https://
	EndPointPort            = "ENDPOINT_PORT"     // 80,8080,...
	EndPointHost            = "ENDPOINT_HOST"
	CfgDefaultPort          = 8080 // default port number
	DefaultEndpointProtocol = "http://"
)

type SystemInfoService interface {
	Init() error
	GetListenAddress() string
	GetOriginAllowed() string
	GetString(name string) string
	GetInt64(name string, defVal int64) int64
	GetBool(name string) bool
	GetMinioCredentials() (*entities.MinioStorageCreds, error)
	GetInstanceId() string
	GetKubernetesConfig() (*entities.KubernetesConfig, error)
	GetDiscoveryConfig() (*entities.NotificationConfig, error)
	GetCaptureConfig() entities.CaptureServiceConfig
	GetApiKey() string
	GetCaptureControllerConfig() entities.CaptureControllerConfig
}

// common functions

// NewSystemInfoService
// creates an interface instance
func NewSystemInfoService() (SystemInfoService, error) {
	s := &systemInfoServiceImpl{
		systemInfoMap: make(map[string]interface{}),
		instanceId:    utils.MakeUniqueId(),
	}
	log.Printf("instance ID:%s", s.instanceId)
	if err := s.Init(); err != nil {
		log.Error("Failed to read system info: " + err.Error())
		return nil, err
	}
	return s, nil
}

// systemInfoServiceImpl an interface implementation
type systemInfoServiceImpl struct {
	systemInfoMap map[string]interface{} // parameters
	instanceId    string
}

// extractBoolDef
// extracts bool value from string with default value
func extractBoolDef(v string, defVal bool) bool {
	if v == view.EmptyString {
		return defVal
	}
	val, err := strconv.ParseBool(v)
	if err != nil {
		return defVal
	}
	return val
}

// extractBool
// extracts bool value from string. error, empty or absent value means 'false'
func extractBool(v string) bool {
	return extractBoolDef(v, false)
}

// fileExists
// validates that file exists and is readable
//func fileExists(fileName string) error {
//	fh, err := os.Open(fileName)
//	defer func(fh *os.File) {
//		_ = fh.Close()
//	}(fh)
//	return err
//}

// interface functions

// Init
// loads configuration from the environment
func (g systemInfoServiceImpl) Init() error {
	// production mode (enable by default)
	g.systemInfoMap[ProductionMode] = extractBoolDef(os.Getenv(ProductionMode), true)
	// configuration parameters without validation
	g.systemInfoMap[OriginAllowed] = os.Getenv(OriginAllowed)
	// internal key for gossips
	g.systemInfoMap[InternalKey] = os.Getenv(InternalKey)

	home := os.Getenv("HOME")
	if home == "" {
		home = "."
	}
	var err error = nil
	kubeconfig := os.Getenv(KubeConfig) // check environment
	kubeconfig, err = entities.ValidateKubeConfig(kubeconfig, true)
	if err != nil {
		log.Fatalf("improper kube configuration path '%s'. Error: %v", kubeconfig, err)
	} else {
		g.systemInfoMap[KubeConfig] = kubeconfig // add value if it is proper
		nodeNamePrefix := os.Getenv(KubeNodeNamePrefix)
		if nodeNamePrefix == view.EmptyString {
			log.Fatalf("unable to continue with empty node name filter. Please set value for %s", KubeNodeNamePrefix)
		} else {
			g.systemInfoMap[KubeNodeNamePrefix] = nodeNamePrefix
		}
		if g.GetString(InternalKey) == view.EmptyString {
			log.Fatalf("value for %s required for sending gossips since %s is configured", InternalKey, KubeConfig)
		}
		g.systemInfoMap[KubeNameSpace] = os.Getenv(KubeNameSpace)
		g.systemInfoMap[KubeSecurityContext] = os.Getenv(KubeSecurityContext)
	}
	// capture
	iface := os.Getenv(CaptureInterface)
	switch iface {
	case view.EmptyString:
		iface = view.CaptureInterfaceAny
	case view.CaptureInterfaceDetect:
		{ // get the first interface with an IPv4 or IPv6 address
			aInterfaceList, err := capture.LocalInterfaces(false)
			if err == nil {
				iface = aInterfaceList[0]
			} else {
				return err
			}
		}
	default:
		{ // ensure that the given value is an interface name
			aInterfaceList, err := capture.LocalInterfaces(false)
			if err == nil {
				j := -1
				for i, v := range aInterfaceList {
					if iface == v {
						j = i
						break
					}
				}
				if j < 0 {
					return fmt.Errorf("unknown interface or no IPv4/IPv6 address on interface")
				}
			} else {
				return err
			}
		}
	}
	// an interface selected or set to CaptureInterfaceAny
	g.systemInfoMap[CaptureInterface] = iface
	g.systemInfoMap[CaptureDirectory] = os.Getenv(CaptureDirectory)
	g.systemInfoMap[CaptureFileCompression] = extractBool(os.Getenv(CaptureFileCompression))
	// S3/Minio
	g.systemInfoMap[MinioAccessKeyId] = os.Getenv(MinioAccessKeyId)
	g.systemInfoMap[MinioSecretAccessKey] = os.Getenv(MinioSecretAccessKey)
	g.systemInfoMap[MinioCrt] = os.Getenv(MinioCrt)
	g.systemInfoMap[MinioEndpoint] = os.Getenv(MinioEndpoint)
	g.systemInfoMap[MinioBucketName] = os.Getenv(MinioBucketName)
	g.systemInfoMap[MinioStorageActive] = extractBool(os.Getenv(MinioStorageActive))
	apiKey := os.Getenv(APIkey)
	if apiKey == view.EmptyString {
		if g.GetBool(ProductionMode) {
			log.Fatalf("Unable to load API key. That will be unsafe in production mode")
		} else {
			log.Warnln("API key empty or not present")
		}
	} else {
		g.systemInfoMap[APIkey] = apiKey
	}
	// ListenAddress a.k.a. endpoint
	sla := os.Getenv(ListenAddress)
	if sla == view.EmptyString {
		return fmt.Errorf("unable to use empty listen address")
	}
	const (
		reIndexProto = 2
		reIndexHost  = 3
		reIndexPort  = 5
	)
	re := regexp.MustCompile(`^((http://|https://)?([^:]+))?(:(\d+))?$`)
	if matches := re.FindStringSubmatch(sla); matches != nil {
		g.systemInfoMap[ListenAddress] = sla
		if len(matches[reIndexProto]) > 0 {
			g.systemInfoMap[EndPointProto] = matches[reIndexProto]
		} else {
			g.systemInfoMap[EndPointProto] = DefaultEndpointProtocol
		}
		g.systemInfoMap[EndPointHost] = matches[reIndexHost]
		nPort, err := strconv.ParseInt(matches[reIndexPort], 10, 64)
		if err != nil || nPort <= 0 {
			nPort = CfgDefaultPort
			log.Warnf("improper value '%s' passed as port number. using default port: %d", matches[reIndexPort], nPort)
		}
		g.systemInfoMap[EndPointPort] = nPort
	} else {
		return fmt.Errorf("invalid listen address: %s", sla)
	}

	captureSnapLen := os.Getenv(CaptureSnapLen)
	if len(captureSnapLen) > 0 {
		var err error = nil
		capSnapLen, err := strconv.ParseInt(captureSnapLen, 10, 64)
		if err != nil {
			return fmt.Errorf("improper number format for %s => '%s' (%v)", CaptureSnapLen, captureSnapLen, err)
		}
		if capSnapLen < 0 {
			return fmt.Errorf("negative capture file size (%s) is not allowed", captureSnapLen)
		}
		g.systemInfoMap[CaptureSnapLen] = capSnapLen
	}
	return nil
}

// GetListenAddress
// returns string value for ListenAddress
func (g systemInfoServiceImpl) GetListenAddress() string {
	return g.systemInfoMap[ListenAddress].(string)
}

// GetOriginAllowed
// returns string value for OriginAllowed
func (g systemInfoServiceImpl) GetOriginAllowed() string {
	return g.systemInfoMap[OriginAllowed].(string)
}

// GetString
// returns string by name or empty string when not found
func (g systemInfoServiceImpl) GetString(name string) string {
	if v, ok := g.systemInfoMap[name]; ok {
		return v.(string)
	}
	return ""
}

// GetInt64
// returns int64 by name or 0 when not found
func (g systemInfoServiceImpl) GetInt64(name string, defVal int64) int64 {
	if v, ok := g.systemInfoMap[name]; ok {
		return v.(int64)
	}
	return defVal
}

// GetBool
// get bool value from configuration
func (g systemInfoServiceImpl) GetBool(name string) bool {
	if v, ok := g.systemInfoMap[name]; ok {
		return v.(bool)
	}
	return false
}

// GetMinioCredentials
// constructs MINIO credentials from configuration
func (g systemInfoServiceImpl) GetMinioCredentials() (*entities.MinioStorageCreds, error) {
	//if len(sResult) > 0 && !g.GetBool(MinioStorageActive) {
	//	return nil, fmt.Errorf("%s will always require S3/minio configured and turned on", sResult)
	//}
	return &entities.MinioStorageCreds{
		BucketName:           g.GetString(MinioBucketName),
		IsActive:             g.GetBool(MinioStorageActive),
		Endpoint:             g.GetString(MinioEndpoint),
		Crt:                  g.GetString(MinioCrt),
		AccessKeyId:          g.GetString(MinioAccessKeyId),
		SecretAccessKey:      g.GetString(MinioSecretAccessKey),
		CompressBeforeUpload: !g.GetBool(CaptureFileCompression),
	}, nil
}

// GetInstanceId
// returns unique instance Id, generated at start
func (g systemInfoServiceImpl) GetInstanceId() string {
	return g.instanceId
}

func (g systemInfoServiceImpl) GetKubernetesConfig() (*entities.KubernetesConfig, error) {
	kubeConfig := g.GetString(KubeConfig)
	_, err := entities.ValidateKubeConfig(kubeConfig, false)
	return &entities.KubernetesConfig{
		Kubeconfig:          kubeConfig,
		KubeNameSpace:       g.GetString(KubeNameSpace),
		KubeSecurityContext: g.GetString(KubeSecurityContext),
		KubeNodeNamePrefix:  g.GetString(KubeNodeNamePrefix),
	}, err
}

func (g systemInfoServiceImpl) GetDiscoveryConfig() (*entities.NotificationConfig, error) {
	kubeconfig, err := g.GetKubernetesConfig()
	if err == nil {
		addrList, err := capture.LocalAddrMap()
		if err != nil {
			return nil, fmt.Errorf("unable to local addresses. Error: %v", err)
		}
		return &entities.NotificationConfig{
			KubernetesConfig: *kubeconfig,
			APIkey:           g.GetApiKey(),
			EndPointPort:     int(g.GetInt64(EndPointPort, CfgDefaultPort)),
			EndPointProto:    g.GetString(EndPointProto),
			AddrList:         addrList,
			InternalKey:      g.GetString(InternalKey),
		}, nil
	}
	return nil, err
}

func (g systemInfoServiceImpl) GetCaptureConfig() entities.CaptureServiceConfig {
	iface := g.GetString(CaptureInterface)
	snapLen := int(g.GetInt64(CaptureSnapLen, int64(view.DefaultSnapLenBytes)))
	log.Printf("Interface   :'%s' configured", iface)
	log.Printf("Instance Id :%s", g.instanceId)
	log.Printf("Snapshot len:%d", snapLen)
	return entities.CaptureServiceConfig{
		NetworkInterface:      iface,
		WorkDirectory:         g.GetString(CaptureDirectory),
		SnapshotLen:           snapLen,
		OutputFileCompression: g.GetBool(CaptureFileCompression),
		InstanceId:            g.instanceId,
	}
}

func (g systemInfoServiceImpl) GetApiKey() string {
	return g.GetString(APIkey)
}

func (g systemInfoServiceImpl) GetCaptureControllerConfig() entities.CaptureControllerConfig {
	return entities.CaptureControllerConfig{
		APIkey:         g.GetApiKey(),
		InternalKey:    g.GetString(InternalKey),
		ProductionMode: g.GetBool(ProductionMode),
	}
}
