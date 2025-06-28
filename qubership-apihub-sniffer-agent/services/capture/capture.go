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

// Package capture
package capture

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/kube_service"

	"github.com/Netcracker/qubership-apihub-sniffer-agent/entities"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/cloud_storage"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/services/name_resolver"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/utils"
	"github.com/Netcracker/qubership-apihub-sniffer-agent/view"
	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// fileWriteErr a log message format string
	fileWriteErr = "Unable to convert and write %s header. Error:%v"
	// signedInt32 restrict int value to int32_t max
	signedInt32 = 0x7fffffff
	// unsignedInt32 restrict int value to uint32_t max
	unsignedInt32 = 0xffffffff
	// smallReportTimeOut small timeout to report capture status back
	smallReportTimeOut = time.Millisecond * 500
)

// Capture public interface
type Capture interface {
	StartCapture(req entities.CaptureInstanceConfig, wsChan chan string) error
	StopCapture(id string) (view.CallResult, error)
	GetStatus() view.CallResult
	SaveCaptureMedata(fileName string, fileBody []byte) error
}

// active capture
type activeCapture struct {
	captureConfig entities.CaptureInstanceConfig // dynamic part of the configuration, changed from request to request
	state         view.CaptureState              // capture state
	storage       cloud_storage.CloudStorage     // S3 bucket to save capture files
	packets       chan gopacket.Packet           // packet data source
	repChan       chan string                    // command result report channel
	cmdChan       chan string                    // stop command channel
	wsChan        chan string                    // webservice notification channel
	lock          sync.Mutex                     // mt protection
	nr            name_resolver.NameResolver     // cloud (kubernetes) name resolver
}

// underlying type for public interface
type captureInternal struct {
	serviceConfig entities.CaptureServiceConfig // static part of the configuration
	storage       cloud_storage.CloudStorage    // S3 bucket to save capture files
	repChan       chan string                   // command result report channel
	cmdChan       chan string                   // stop command channel
	active        *activeCapture                // an active capture instance
	nr            name_resolver.NameResolver    // cloud (kubernetes) name resolver
	ks            kube_service.K8Service        // kubernetes service
}

// Capture file related structures
// file starting header
type pcapFileHeader struct {
	magic     uint32 // file type magic 0xA1B23C4D
	verMajor  int16  // major version, 2 for now
	verMinor  int16  // minor version 4 for now
	reserved1 int32  // reserved, always 0
	reserved2 int32  // reserved, always 0
	snapLen   int32  // snapshot length (maximum stored packet size)
	linkType  int16  // link layer type, 1 (LINK_TYPE_ETHERNET) for this
	fcs       int16  // FCS len [0:3], R[4], P[5], reserved [6:15]
}

// packet starting header
type pcapPacket2write struct {
	seconds   int32 // timestamp.seconds
	fractions int32 // timestamp.fractions (microseconds or nanoseconds)
	capLen    int32 // captured packet length
	origLen   int32 // original packet length
}

// Common functions

// NewCapture
// creates a new packet capture service instance
// always returns a new instance with an optional error indicator
func NewCapture(staticConfig entities.CaptureServiceConfig, s3 cloud_storage.CloudStorage, ks kube_service.K8Service, nr name_resolver.NameResolver) (Capture, error) {
	var returnedError error = nil
	if len(staticConfig.WorkDirectory) > 1 {
		fileName := path.Join(staticConfig.WorkDirectory, "test.tst")
		fh, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
		defer func(fh *os.File) {
			_ = fh.Close()
		}(fh)
		_ = os.Remove(fileName)
		if err != nil {
			returnedError = fmt.Errorf("directory '%s' is not writable, error: %v",
				staticConfig.WorkDirectory, err)
		}
	} else {
		returnedError = fmt.Errorf("empty directory is not allowed")
	}
	return &captureInternal{
		serviceConfig: staticConfig,
		storage:       s3,
		repChan:       make(chan string, 2),
		cmdChan:       make(chan string, 2),
		active:        nil,
		nr:            nr,
		ks:            ks,
	}, returnedError
}

// flushChannel
// removes unsolicited extra data from the given channel
func flushChannel(repChan chan string) {
	attempts := 2
	for attempts != 0 {
		select {
		case _ = <-repChan:
			break // log.Warnf("unexpected message: %s", errStr)
		case <-time.After(time.Millisecond * 500):
			attempts--
		}
	}
}

// pushChannel
// "lock-free" channel messaging
func pushChannel(repChan chan string, msg string, timeOut time.Duration) {
	select {
	case repChan <- msg:
	case <-time.After(timeOut):
		log.Warnf("timeout to report: %s", msg)
	}
}

// LocalAddrMap - list local addresses
// returns a map of IPv4/IPv6 -> interface name
func LocalAddrMap() (map[string]string, error) {
	localAddrMap := make(map[string]string)
	interfaces, err := net.Interfaces()
	if err != nil {
		return localAddrMap, err
	}
	rea := regexp.MustCompile(`^([^/]+)/([^/]+)$`)
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			log.Debugf("unable to get addresses for interface %s, error: %v", i.Name, err)
			continue
		}
		// for any interface with IPv4 of IPv6 addresses
		for _, a := range addresses {
			if parts := rea.FindStringSubmatch(a.String()); parts != nil {
				log.Debugf("address: %s", parts[1])
				localAddrMap[parts[1]] = i.Name // without mask length
			} else {
				log.Debugf("something: %s", a.String())
				localAddrMap[a.String()] = i.Name // something
			}
		}
	}
	if len(localAddrMap) < 0 {
		err = fmt.Errorf("no IPv4 or IPv6 address detected")
	} else {
		err = nil
	}
	return localAddrMap, err
}

// LocalInterfaces - list local interfaces into string array
// skip interfaces without IP address if parameter is false
func LocalInterfaces(all bool) ([]string, error) {
	var ret []string = nil
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	res := make(map[string]string)
	ipre := regexp.MustCompile(`(?m)(\d+\.){3}(\d+)`)
	for _, i := range interfaces {
		if all {
			res[i.Name] = "All"
			continue
		}
		addresses, err := i.Addrs()
		if err != nil {
			continue
		}
		if (i.Flags&net.FlagLoopback) == net.FlagLoopback || (i.Flags&net.FlagMulticast) != net.FlagMulticast {
			continue // skip loop-back or tunnel interfaces
		}
		if strings.HasPrefix(i.Name, "tun") || strings.HasPrefix(i.Name, "docker") {
			continue // skip tunnel or docker interfaces
		}
		// for any interface with IPv4 of IPv6 addresses
		for _, a := range addresses {
			interfaceAddr := a.String()
			if interfaceAddr == view.EmptyString {
				continue
			}
			if ipre.MatchString(interfaceAddr) {
				res[i.Name] = interfaceAddr
			}
		}
	}
	if len(res) > 0 {
		ret = make([]string, len(res))
		j := 0
		for v := range res {
			ret[j] = v
			j++
		}
		return ret, nil
	}
	return nil, fmt.Errorf("no interface with IPv4 or IPv6 detected")
}

// capturePackets
// goroutine function
// do the network packet capturing and write data into a local file
func capturePackets(instance *activeCapture) {
	defer func() {
		select {
		case instance.wsChan <- instance.captureConfig.Id:
			break // command accepted
		case <-time.After(time.Second * 5): // channel writing timeout
			log.Warnf("unable to notify webservice about capture %s end", instance.captureConfig.Id)
		}
	}()
	handle, err := pcap.OpenLive(instance.captureConfig.NetworkInterface, int32(instance.captureConfig.SnapshotLen),
		true, instance.captureConfig.Duration)
	if err != nil {
		instance.state = view.CapStateFailed
		log.Errorf("Unable to open capture at '%s'. Error: '%v'", instance.captureConfig.NetworkInterface, err)
		//time.Sleep(senderTimeOut)
		pushChannel(instance.repChan, fmt.Sprintf("Unable to open capture at '%s'. Error: '%v'",
			instance.captureConfig.NetworkInterface, err), smallReportTimeOut)
		return
	} else {
		log.Printf("Capturing packets at device '%s'. Snapshot length is %d",
			instance.captureConfig.NetworkInterface, instance.captureConfig.SnapshotLen)
	}
	defer handle.Close()
	if instance.captureConfig.Filter != view.EmptyString {
		log.Debugf("Filter to compile: '%s'", instance.captureConfig.Filter)
		if err := handle.SetBPFFilter(instance.captureConfig.Filter); err != nil {
			instance.state = view.CapStateFailed
			log.Errorf("Unable to set filter '%s'. Error: '%v'", instance.captureConfig.Filter, err)
			pushChannel(instance.repChan, fmt.Sprintf("Unable to set filter '%s'. Error: '%v'",
				instance.captureConfig.Filter, err), smallReportTimeOut)
			return
		} else {
			log.Printf("Using filter: '%s'", instance.captureConfig.Filter)
		}
	}
	instance.packets = gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	nPkt := 0  // captured packets counter
	nFile := 0 // file number
	instance.state = view.CapStateRunning
	nameSuffix := view.EmptyString // file name suffix empty by default
	if instance.captureConfig.OutputFileCompression {
		nameSuffix = view.GzipSuffix // but have a value when file compression is on
	}
	captureStart := time.Now()
	captureStop := captureStart.Add(instance.captureConfig.Duration)
	for instance.state == view.CapStateRunning {
		// base file name
		fileBaseName := fmt.Sprintf("%s_%s_%02d.pcap", instance.captureConfig.Id,
			instance.captureConfig.InstanceId, nFile)
		// file name with path and suffix
		fileName := path.Join(instance.captureConfig.WorkDirectory, fileBaseName+nameSuffix)
		nFile++
		fh, fileError := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
		if fileError != nil {
			instance.state = view.CapStateFailed
			if nPkt == 0 { // first file - report failure
				//time.Sleep(senderTimeOut)
				log.Errorf("Unable to open '%s'. Error: '%v'", fileName, fileError)
				pushChannel(instance.repChan, fmt.Sprintf("Unable to open '%s'. Error: '%v'", fileName, fileError), smallReportTimeOut)
			} else {
				log.Errorf("Unable to open '%s'. Error: '%v'", fileName, fileError)
			}
			break
		} else {
			log.Printf("Writing packets to the file '%s'", fileName)
		}
		var ow io.Writer
		// creating buffered writer
		ow = bufio.NewWriter(fh) // default buffered writer
		if ow == nil {
			log.Warnf("unable to create buffered writer for '%s'", fileName)
			ow = fh // fall back to raw file
		}
		var zw *gzip.Writer = nil
		if instance.captureConfig.OutputFileCompression {
			zw = gzip.NewWriter(ow)
			zw.Name = fileBaseName // set filename in archive metadata
		}
		if nPkt == 0 { // first file - report failure
			pushChannel(instance.repChan, view.EmptyString, smallReportTimeOut)
		}
		fileSize := int64(0)
		n := 0 // to receive new captured packet count
		if instance.captureConfig.OutputFileCompression && zw != nil {
			n, fileSize = instance.capturePacketsToFile(zw, nPkt, captureStart, captureStop)
		} else {
			n, fileSize = instance.capturePacketsToFile(ow, nPkt, captureStart, captureStop)
		}
		if instance.captureConfig.OutputFileCompression && zw != nil {
			err = zw.Flush()
			if err != nil {
				log.Errorf("unable to flush compressed stream. Error: %v", err)
			}
			if err := zw.Close(); err != nil {
				log.Errorf("unable to close compressed stream. Error: '%v'", err)
			}
		}
		if n != nPkt { // for non-empty files only
			// binary files will always have some junk bytes at the end
			err = fh.Truncate(fileSize) // remove these bytes with truncate
			if err != nil {
				log.Warnf("unable to truncate file '%s' to size %d", fileName, fileSize)
			}
		}
		err = fh.Close()
		if err != nil {
			log.Errorf("Unable to close '%s'. Error: '%v'\n", fileName, err)
		}
		if n == nPkt { // packet count not changed -> file contains only header -> file is empty
			log.Warnf("empty file '%s' discarded", fileName)
			err = os.Remove(fileName)
			if err != nil {
				log.Warnf("unable to remove file '%s'. Error: '%v'\n", fileName, err)
			}
		} else {
			nPkt = n                             // update captured packet count
			instance.storage.StoreFile(fileName) // store non-empty file in s3/minio
		}
		if instance.captureConfig.FileSize > 0 && nPkt > instance.captureConfig.FileSize {
			if instance.state == view.CapStateRunning {
				instance.state = view.CapStateCompleted
			}
		}
		if time.Now().After(captureStop) {
			log.Debugf("time is up: %s", time.Since(captureStart).String())
			if instance.state == view.CapStateRunning {
				instance.state = view.CapStateCompleted
			}
		}
		log.Debugf("Packets captured:%d, intermediate state: %s", nPkt, view.CapStateToReqStatus(instance.state))
	}
	if instance.state == view.CapStateStopping {
		instance.state = view.CapStateStopped
	}
	log.Printf("capture '%s' funished with state: %s, time spent %s",
		instance.captureConfig.Id, view.CapStateToReqStatus(instance.state), time.Since(captureStart).String())
	if instance.nr != nil && (instance.state == view.CapStateStopped || instance.state == view.CapStateCompleted) {
		log.Infof("flushing names...")
		instance.nr.FlushNames(instance.captureConfig)
		log.Infof("names flushed")
	}
	select {
	case instance.repChan <- view.EmptyString:
		break // caller notified
	case <-time.After(time.Second * 30): // channel writing timeout
		log.Warnf("unable to notify capture service about capture %s end", instance.captureConfig.Id)
	}
}

// Capture interface implementation

// StartCapture
// starts a parallel packet capturing or report an error
func (cap *captureInternal) StartCapture(req entities.CaptureInstanceConfig, controllerChan chan string) error {
	if req.Duration < view.MinCaptureDuration && req.Duration != pcap.BlockForever {
		log.Warnf("improper duration (%v) passed. falling back to default (%s)",
			req.Duration, view.DefaultCaptureDuration.String())
		req.Duration = view.DefaultCaptureDuration
	}
	if req.FileSize <= 0 {
		req.FileSize = view.DefaultFileDataSize
	}
	if req.SnapshotLen <= 0 {
		req.SnapshotLen = view.DefaultSnapLenBytes
	}
	if req.NetworkInterface == view.EmptyString {
		req.NetworkInterface = cap.serviceConfig.NetworkInterface
	}
	if req.Id == view.EmptyString {
		return fmt.Errorf("unable to use empty Id")
	}
	if cap.active != nil {
		cid := cap.active.captureConfig.Id
		if cid == req.Id {
			if cap.active.state == view.CapStateRunning || cap.active.state == view.CapStateStarting {
				return nil // this capture id is running
			}
		} else {
			if cap.active.state == view.CapStateRunning || cap.active.state == view.CapStateStarting {
				if cid != view.EmptyString && req.Id != cid {
					return fmt.Errorf("another capture '%s' has already started", cid)
				}
			}
		}
	}
	req.InstanceId = cap.serviceConfig.InstanceId // copy application instance id to capture
	cap.active = &activeCapture{
		captureConfig: req,
		state:         view.CapStateStarting,
		storage:       cap.storage,
		packets:       nil,
		repChan:       cap.repChan,
		cmdChan:       cap.cmdChan,
		lock:          sync.Mutex{},
		nr:            cap.nr,
		wsChan:        controllerChan,
	}
	flushChannel(cap.repChan)
	utils.SafeAsync(func() {
		var (
			err      error = nil
			attempts       = 2
		)

		if len(cap.active.captureConfig.Namespaces) > 0 {
			// to capture on all devices
			cap.active.captureConfig.NetworkInterface = view.CaptureInterfaceAny
			// resolve IP fot the specified namespace only
			for attempts > 0 {
				attempts--
				var (
					ips             []string
					tips            []string
					errGetNamespace error = nil
				)
				if cap.active.nr != nil {
					for _, nsName := range cap.active.captureConfig.Namespaces {
						tips, errGetNamespace = cap.ks.AcquireNamespaceAddresses(nsName)
						if errGetNamespace != nil {
							log.Errorf("unable to get namespace '%s' ips: %s", nsName, errGetNamespace.Error())
							break // break the loop when error
						}
						log.Debugf("ns:%s, IPs:%s\n", nsName, strings.Join(tips, "|"))
						// append target
						ips = append(ips, tips...)
					}
				} else {
					errGetNamespace = fmt.Errorf("no name resolution available for namespaces '%s'",
						strings.Join(cap.active.captureConfig.Namespaces, view.ArrayJoinSeparator))
				}
				if errGetNamespace != nil {
					if attempts == 0 {
						err = fmt.Errorf("unable to get namespace ips. Error: '%v'", errGetNamespace)
						cap.active.setState(view.CapStateFailed)
						cap.active.repChan <- err.Error()
						break
					}
				} else {
					// update the filter
					log.Debugf("filter ip address count: %d", len(ips))
					if len(ips) > 0 {
						// sort non-empty IP address array
						sort.Strings(ips)
						filterStr := "("
						prevIp := ""
						for idx, ip := range ips {
							if prevIp == ip {
								continue // skip duplicates in sorted array
							}
							prevIp = ip
							log.Debugf("Got %d IP %s", idx, ip)
							if idx == 0 {
								filterStr += fmt.Sprintf("host %s", ip)
							} else {
								filterStr += fmt.Sprintf(" or host %s", ip)
							}
						}
						filterStr += ")"
						if cap.active.captureConfig.Filter != view.EmptyString {
							cap.active.captureConfig.Filter += " and " + filterStr
						} else {
							cap.active.captureConfig.Filter = filterStr
						}
					} else {
						log.Errorf("unable to extend filter with namespaces")
					}
					break
				}
			}
		}
		if len(cap.active.captureConfig.Filter) > view.FilterMaxLength {
			err = fmt.Errorf("unable to proceed: filter expression is too big")
		}
		if err == nil {
			capturePackets(cap.active)
		} else {
			log.Errorf("unable to start capture %s : %v", cap.active.captureConfig.Id, err)
			cap.active.setState(view.CapStateFailed)
			cap.active.repChan <- err.Error()
		}
	}) // +SafeAsync
	select {
	case errStr := <-cap.repChan:
		if errStr != view.EmptyString {
			return fmt.Errorf(errStr)
		}
	case <-time.After(time.Second * 5):
		return fmt.Errorf("capture start did not confirmed. timeout exceeded")
	}
	return nil
}

// StopCapture
// request to stop packet capturing
func (cap *captureInternal) StopCapture(id string) (view.CallResult, error) {
	var err error = nil
	result := view.CallResult{Status: view.RequestStatusNone, Id: view.EmptyString}
	instance := cap.active
	if instance == nil { // no active capture - nothing to stop
		log.Warnln("no active capture to stop")
		return result, nil
	}
	if instance.captureConfig.Id != id {
		err = fmt.Errorf("no capture '%s' started", id)
		log.Warnln(err.Error())
		return result, err
	}
	if instance.state != view.CapStateRunning && instance.state != view.CapStateStarting {
		result.Status = view.CapStateToReqStatus(instance.state)
	} else {
		// sending request to stop with timeout
		select {
		case cap.cmdChan <- view.EmptyString:
			break // command accepted
		case <-time.After(time.Second * 5):
			instance.setState(view.CapStateStopping) // writing timeout - force to stop
		}
		// wait for request to confirm
		select {
		case <-cap.repChan: // confirmed
			{
				result.Status = view.CapStateToReqStatus(instance.state)
				err = nil
			}
		case <-time.After(time.Second * 30):
			{ // request timed out
				err = fmt.Errorf("request timeout at state: %s", view.CapStateToReqStatus(instance.state))
				result.Status = view.CapStateToReqStatus(instance.state)
				//default: // impossible state
				//	err = fmt.Errorf("on the edge at state:%s", view.CapStateToReqStatus(instance.state))
			}
		}
	}
	cap.active = nil // all things have done - drop active instance
	return result, err
}

// SaveCaptureMedata
// create a medata file and request to store it on S3/Minio
func (cap *captureInternal) SaveCaptureMedata(fileName string, fileBody []byte) error {
	pathName := path.Join(cap.serviceConfig.WorkDirectory, fileName)
	mdf, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	written := 0
	written, err = mdf.Write(fileBody)
	closeErr := mdf.Close()
	if err == nil {
		if written != len(fileBody) {
			err = fmt.Errorf("unable to write capture metadata to file %s, %d bytes written", fileName, written)
		} else {
			cap.storage.StoreFile(pathName)
			err = closeErr
		}
	}
	return err
}

// GetStatus
// returns the current packet capture status
func (cap *captureInternal) GetStatus() view.CallResult {
	instance := cap.active
	if instance != nil {
		instance.lock.Lock()
		defer instance.lock.Unlock()
		return view.CallResult{Status: view.CapStateToReqStatus(instance.state), Id: instance.captureConfig.Id}
	}
	return view.CallResult{Status: view.CapStateToReqStatus(view.CapStateNone), Id: view.EmptyString}
}

// decodeIPv4FeedBack
// libpcap packet decoder required interface
type decodeIPv4FeedBack struct {
	Truncated bool
}

// SetTruncated
// required method to maintain interface
func (df *decodeIPv4FeedBack) SetTruncated() {
	df.Truncated = true
}

// activeCapture member functions

// capturePacketsToFile
// capture packets into an opened file with file size limit checking
func (instance *activeCapture) capturePacketsToFile(zw io.Writer, nPkt int, captureStart, captureStop time.Time) (int, int64) {
	// write file header
	fileHeader := pcapFileHeader{
		magic:     uint32(0xA1B23C4D), // recommended value for microseconds
		verMajor:  int16(2),           // recommended value
		verMinor:  int16(4),           // recommended value
		reserved1: int32(0),           // gmt to local correction; this is always 0
		reserved2: int32(0),           // accuracy of timestamps; this is always 0
		snapLen:   int32(instance.captureConfig.SnapshotLen & signedInt32),
		fcs:       int16(0), // magic value
		linkType:  int16(1), // ethernet
	}
	err := binary.Write(zw, binary.LittleEndian, &fileHeader)
	if err != nil {
		log.Printf(fileWriteErr, "file", err)
	}
	fileDataSize := int64(binary.Size(fileHeader)) //  start from sizeof(pcapFileHeader)
	for {
		if time.Now().After(captureStop) {
			log.Debugf("time limit exceeded %s", time.Since(captureStart).String())
			break
		}
		if instance.state != view.CapStateRunning {
			log.Printf("current state changed to %s", view.CapStateToReqStatus(instance.state))
			break // stop request
		}
		var pkt gopacket.Packet = nil
		waitStatus := 0
		select {
		case pkt = <-instance.packets:
			waitStatus = 1 // got packet
		case <-instance.cmdChan:
			{
				instance.setState(view.CapStateStopping)
				waitStatus = 2 // stop requested
			}
		case <-time.After(time.Millisecond * 400):
			waitStatus = -1 // got timeout
		}
		if waitStatus != 1 {
			continue // no packet captured - continue
		}
		packetBytes := pkt.Data() //[0:pkt.Metadata().CaptureLength]
		t := pkt.Metadata().Timestamp
		if t.IsZero() {
			t = time.Now()
		}
		// access to captured packet via pkt
		ph := pcapPacket2write{
			seconds:   int32(t.Unix() & unsignedInt32),
			fractions: int32(t.UnixMicro() & unsignedInt32),
			capLen:    int32(pkt.Metadata().CaptureLength & signedInt32),
			origLen:   int32(pkt.Metadata().Length & signedInt32),
		}
		fileDataSize += int64(binary.Size(ph)) // update data len with sizeof(pcapPacket2write)
		err = binary.Write(zw, binary.LittleEndian, &ph)
		if err != nil {
			log.Errorf(fileWriteErr, "packet", err)
			instance.setState(view.CapStateFailed)
			break
		}
		if len(packetBytes) != pkt.Metadata().CaptureLength {
			log.Errorf("improper capture packet size (%d instead of %d)", len(packetBytes),
				pkt.Metadata().CaptureLength)
		}
		if pkt.Metadata().CaptureLength > pkt.Metadata().Length {
			log.Errorf("bad capture packet size (%d instead of %d)", pkt.Metadata().Length,
				pkt.Metadata().CaptureLength)
		}
		_, err = zw.Write(packetBytes)
		if err != nil {
			log.Errorf("unable to write bytes for packet %d. Error: '%v'", nPkt, err)
		}
		nPkt++
		// an IP packet required - check it
		layerIPv4 := pkt.Layer(layers.LayerTypeIPv4)
		if layerIPv4 == nil {
			continue // no an IP packet - discard it
		}
		if instance.nr != nil {
			// if name resolver available
			var (
				ipv4 layers.IPv4
				df   = decodeIPv4FeedBack{Truncated: false}
			)
			err := ipv4.DecodeFromBytes(layerIPv4.LayerContents(), &df)
			if err != nil {
				return 0, 0
			}
			// resolve both addresses
			instance.nr.ResolveToName(instance.captureConfig.Id, ipv4.DstIP.String())
			instance.nr.ResolveToName(instance.captureConfig.Id, ipv4.SrcIP.String())
		}
		if instance.captureConfig.PacketCount > 0 && nPkt >= instance.captureConfig.PacketCount {
			log.Printf("Packet capture limit (%d packets) reached. Stopping\n", nPkt)
			break
		}
		if instance.captureConfig.FileSize > 0 {
			fileDataSize += int64(len(packetBytes))
			if fileDataSize >= int64(instance.captureConfig.FileSize) {
				log.Printf("File data size limit (%d) reached %d", instance.captureConfig.FileSize, fileDataSize)
				break
			}
		}
	}
	return nPkt, fileDataSize
}

// setState
// internal, locking state setter
func (instance *activeCapture) setState(status view.CaptureState) {
	instance.lock.Lock()
	instance.state = status
	instance.lock.Unlock()
}
