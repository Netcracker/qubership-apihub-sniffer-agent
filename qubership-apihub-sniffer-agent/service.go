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

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/disk_cache"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/kube_service"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/controllers"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/capture"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/cloud_storage"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/name_resolver"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/neighbour"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/service"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

type serviceStatusType int

const (
	serviceStatusRunning serviceStatusType = iota
	serviceStatusStart
	serviceStatusRestart
)

const restartServiceInterval = 10 * time.Second

func makeServer(systemInfoService service.SystemInfoService, r *mux.Router) *http.Server {
	listenAddr := systemInfoService.GetListenAddress()

	log.Infof("Listen addr = %s", listenAddr)

	var corsOptions []handlers.CORSOption

	corsOptions = append(corsOptions,
		handlers.AllowedHeaders([]string{
			"Connection",
			"Accept-Encoding",
			"Content-Encoding",
			"X-Requested-With",
			controllers.HttpContentType,
			"Authorization"}))

	allowedOrigin := systemInfoService.GetOriginAllowed()
	if allowedOrigin != "" {
		corsOptions = append(corsOptions, handlers.AllowedOrigins([]string{allowedOrigin}))
	}
	corsOptions = append(corsOptions, handlers.AllowedMethods([]string{http.MethodPost, http.MethodGet}))

	return &http.Server{
		Handler:      handlers.CompressHandler(handlers.CORS(corsOptions...)(r)),
		Addr:         listenAddr,
		WriteTimeout: 300 * time.Second,
		ReadTimeout:  30 * time.Second,
	}
}

// init
// initialises logging
func init() {
	basePath := os.Getenv("BASE_PATH")
	if basePath == "" {
		basePath = "."
	}
	mw := io.MultiWriter(os.Stderr, &lumberjack.Logger{
		Filename: path.Join(basePath, "logs", "apihub_sniffer_agent.log"),
		MaxSize:  10, // megabytes
	})
	log.SetFormatter(&prefixed.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
		ForceFormatting: true,
	})
	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = log.InfoLevel
	}
	log.SetLevel(logLevel)
	log.SetOutput(mw)
}

// init
// initialises paas configuration from environment
func init() {
	sourceParams := configloader.YamlPropertySourceParams{ConfigFilePath: "config.yaml"}
	configloader.Init(configloader.BasePropertySources(sourceParams)...)
	piece := configloader.GetKoanf()
	if piece != nil {
		err := configloader.GetKoanf().Set("paas.platform", os.Getenv("PAAS_PLATFORM"))
		if err != nil {
			log.Error(err)
		} else {
			err = configloader.GetKoanf().Set("paas.version", os.Getenv("PAAS_VERSION"))
			if err != nil {
				log.Error(err)
			}
		}
	}
}

func main() {
	actionStr := view.EmptyString
	ipAddress := view.EmptyString
	logLevel := view.EmptyString
	nameSpace := view.EmptyString
	workDir := view.EmptyString
	timeoutVal := time.Second * 10
	flag.StringVar(&actionStr, "action", view.EmptyString, "What needs to be debugged")
	flag.DurationVar(&timeoutVal, "wait-time", time.Second*10, "timeout for actions")
	flag.StringVar(&ipAddress, "address", "127.0.0.1", "an IP address to resolve")
	flag.StringVar(&logLevel, "log-level", "DEBUG", "A logging level: (trace, debug, info, warning, error, fatal, panic)")
	flag.StringVar(&nameSpace, "namespace", os.Getenv(service.KubeNameSpace), "A namespace name to inspect")
	flag.StringVar(&workDir, "work-dir", os.Getenv("WORK_DIR"), "working directory")
	flag.Parse()
	systemInfoService, mandatoryServiceError := service.NewSystemInfoService()
	if mandatoryServiceError != nil {
		log.Fatalf("unable to prepare service configuration '%v'", mandatoryServiceError)
	}
	productionMode := systemInfoService.GetBool(service.ProductionMode)
	// opening S3 somehow
	s3Config, err := systemInfoService.GetMinioCredentials()
	if err != nil {
		log.Fatalln(err)
	}
	var ks kube_service.K8Service = nil
	kc, err := systemInfoService.GetKubernetesConfig()
	if err != nil {
		log.Fatalf("invalid kubernetes config: %v", err)
	}
	if kc.Kubeconfig != entities.KubeConfigOff {
		podCache, err := disk_cache.NewDiskCache(entities.PodCacheName, systemInfoService.GetString(service.CaptureDirectory))
		if err != nil {
			log.Fatalln(err)
		} else {
			log.Printf("disk cache \"%s\" created", entities.PodCacheName)
		}
		ks, err = kube_service.NewKubeService(kc, podCache)
		if err != nil {
			log.Fatalf("Unable to create kubernetes service: %v", err)
		} else {
			if ks != nil {
				log.Printf("kubernetes service activated")
			}
		}
	} else {
		log.Warnf("Kubernetes config is tuned off")
	}
	cs3 := cloud_storage.NewCloudStorage(*s3Config, productionMode) // credentials + production mode flag
	defer cs3.StoreFile(cloud_storage.BreakTheLoop)                 // finish at the end
	var neighbours neighbour.NotificationSender = nil
	if ks != nil {
		discoveryConfig, err := systemInfoService.GetDiscoveryConfig()
		if err == nil {
			log.Println("neighbours notification service activated")
			locals, err := capture.LocalAddrMap()
			if err != nil {
				log.Errorf("unable to get local address map: %v", err)
			}
			neighbours = neighbour.NewNotificationSender(*discoveryConfig, ks, locals)
		} else {
			log.Warningf("neighbours notification was not configured properly. Issue: %v", err)
		}
	} else {
		log.Warningf("neighbours notification was not configured properly. No kubernetes initialized")
	}
	// making name resolver service
	var nr name_resolver.NameResolver = nil
	if ks != nil {
		nr = name_resolver.NewNameResolver(*kc, cs3, ks, systemInfoService.GetInstanceId())
		log.Println("name resolution service activated")
	}
	log.Debugf("webservice")
	if actionStr == view.EmptyString {
		pkt, err := capture.NewCapture(systemInfoService.GetCaptureConfig(), cs3, ks, nr) // static configuration + cloud storage
		if err != nil {
			log.Printf("capture created with error '%v'", err)
		}
		ws := controllers.NewWebService(pkt, neighbours, systemInfoService.GetCaptureControllerConfig())
		failureReportChannel := make(chan string)
		controllerStatus := serviceStatusStart // try to start service
		restartPause := restartServiceInterval // set initial pause
		for {
			if controllerStatus != serviceStatusRunning {
				if controllerStatus == serviceStatusRestart { // when service is restarting
					time.Sleep(restartPause) // make a pause
					restartPause *= 2        // increase interval
				}
				controllerStatus = serviceStatusRunning // mark service as running
				utils.SafeAsync(func() {
					defer func() {
						select {
						case failureReportChannel <- view.EmptyString:
							break // controller failed
						case <-time.After(time.Second * 5): // channel writing timeout
							log.Warnf("unable to notify about controller's failure")
						}
					}()
					r := mux.NewRouter()
					r.SkipClean(true)
					r.UseEncodedPath()
					r.HandleFunc(entities.GossipStartPath, ws.OnStart).Methods(http.MethodPost)
					r.HandleFunc(entities.GossipStopPath, ws.OnStop).Methods(http.MethodPost)
					r.HandleFunc(entities.InterfaceListPath, ws.OnInterfaces).Methods(http.MethodGet)
					r.HandleFunc(entities.NamespacesPath, ws.OnNamespaces).Methods(http.MethodGet)
					r.HandleFunc(entities.CaptureStatus, ws.OnCaptureStatus).Methods(http.MethodGet)
					if !productionMode {
						r.HandleFunc(entities.AddressMapPath, ws.OnAddressMap).Methods(http.MethodGet)
						r.HandleFunc(entities.NeighboursPath, ws.OnNeighbours).Methods(http.MethodGet)
					}
					// set TTL reactions
					r.HandleFunc("/live", ws.OnStatus).Methods(http.MethodGet)
					r.HandleFunc("/ready", ws.OnStatus).Methods(http.MethodGet)
					r.HandleFunc("/startup", ws.OnStatus).Methods(http.MethodGet)
					srv := makeServer(systemInfoService, r)
					log.Fatalf("Service fatal error:%v", srv.ListenAndServe())
				})
			}
			select {
			case _ = <-failureReportChannel:
				{
					log.Error("controller failed unexpectedly")
					controllerStatus = serviceStatusRestart // when failed - ask for a restart
				}
			case <-time.After(time.Hour * 24):
				{
					log.Print("Controller is healthy")
					restartPause = restartServiceInterval // reset interval when service is running
				}
			}

		}
		defer ws.Close()
	} else {
		log.Printf("Debug mode action %s", actionStr)
		switch strings.ToUpper(logLevel) {
		case "TRACE":
			log.SetLevel(log.TraceLevel)
		case "DEBUG":
			log.SetLevel(log.DebugLevel)
		case "INFO":
			log.SetLevel(log.InfoLevel)
		case "WARNING":
			log.SetLevel(log.WarnLevel)
		case "ERROR":
			log.SetLevel(log.ErrorLevel)
		case "FATAL":
			log.SetLevel(log.FatalLevel)
		default:
			log.SetLevel(log.DebugLevel)
		}
		switch actionStr {
		case "list-pods":
			{
				if ks == nil {
					break
				}
				log.Println("listing pods")
				t1 := time.Now()
				list, err := ks.AcquireNamespacePodMap(kc.KubeNameSpace)
				t2 := time.Now()
				if err != nil {
					log.Errorf("Error listing pods: %v for namespace %s", err, kc.KubeNameSpace)
				}
				log.Printf("AcquireNamespacePodList takes %v)", t2.Sub(t1))
				for ii, pod := range list {
					log.Printf("*** %s => %s", ii, pod)
				}
			}
		case "get-ns":
			{
				if ks == nil {
					break
				}
				scanner := bufio.NewScanner(os.Stdin)
				log.Println("listing all")
				t1 := time.Now()
				sip := ks.GetAddressServiceName(ipAddress)
				t2 := time.Now()
				log.Printf("%s belongs to %s (initially takes %v)", ipAddress, sip, t2.Sub(t1))
				for scanner.Scan() {
					fmt.Print("Enter an IP address to resolve > ")
					ipAddress = scanner.Text() // Get the current line of text
					if ipAddress == "" {
						break // Exit loop if an empty line is entered
					}
					t1 = time.Now()
					sip = ks.GetAddressServiceName(ipAddress)
					t2 = time.Now()
					log.Printf("%s belongs to %s (takes %v)", ipAddress, sip, t2.Sub(t1))
				}
				dumpFileName := path.Join(systemInfoService.GetString(service.CaptureDirectory), systemInfoService.GetInstanceId()+"map_dump.txt")
				err = ks.DumpAddressMap(dumpFileName)
				if err != nil {
					log.Errorf("unable to dump address map: %v", err)
				} else {
					log.Println("dump address map done. storing in the S3/Minio")
					cs3.StoreFile(dumpFileName)
				}
			}
		case "namespace-ip":
			{
				if ks == nil {
					break
				}
				ipList, err := ks.AcquireNamespaceAddresses(nameSpace)
				if err == nil {
					for idx, ip := range ipList {
						log.Infof("%d %s", idx, ip)
					}
				} else {
					log.Errorf("Error listing pods: %v", err)
				}
			}
		default:
			log.Errorf("don't know how to handle action %v", actionStr)
		}
	}
}
