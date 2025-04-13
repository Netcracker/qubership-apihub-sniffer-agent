/*
Copyright 2024 NEC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
	// empty string
	sEmpty = ""
	// default filter string
	defFilter = "(tcp port 80 or tcp port 8080) and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"
	// default output file name
	defFile = "tcp.pcap"
	// default packet count limit
	defPacketCount = 10
	// a log message format string
	fileWriteErr  = "Unable to convert and write %s header. Error:%v"
	signedInt32   = 0x7fffffff
	unsignedInt32 = 0xffffffff
)

// application configuration
type configData struct {
	interfaceName  string        // network interface name
	maxPacketCount int           // amount of packets to be captured
	filter         string        // tcpdump-alike filter string
	fileName       string        // output file name
	captureSize    int           // capture buffer limit (a.k.a. SnapshotLen)
	CapDuration    time.Duration // capture duration limit
	listInterfaces bool          // list interfaces and exit
}

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

type pcapPacket2write struct {
	seconds   int32 // timestamp.seconds
	fractions int32 // timestamp.fractions (microseconds or nanoseconds)
	capLen    int32 // captured packet length
	origLen   int32 // original packet length
}

// application configuration instance
var appConfig = configData{
	interfaceName:  sEmpty,
	filter:         defFilter,
	fileName:       defFile,
	maxPacketCount: defPacketCount,
	captureSize:    defaultSnapLen,
	CapDuration:    pcap.BlockForever,
	listInterfaces: false,
}

const magicMicroseconds = 0xA1B2C3D4
const versionMajor = 2
const versionMinor = 4

func WriteFileHeader(w *io.Writer, snaplen uint32, linktype layers.LinkType) error {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], magicMicroseconds)
	binary.LittleEndian.PutUint16(buf[4:6], versionMajor)
	binary.LittleEndian.PutUint16(buf[6:8], versionMinor)
	// bytes 8:12 stay 0 (timezone = UTC)
	// bytes 12:16 stay 0 (sigfigs is always set to zero, according to
	//   http://wiki.wireshark.org/Development/LibpcapFileFormat
	binary.LittleEndian.PutUint32(buf[16:20], snaplen)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(linktype))
	err := binary.Write(*w, binary.LittleEndian, buf)
	return err
}

// getPacketz capture network packets on the interface with filter, write packets into a file
func getPacketz(devName string, filterExpr string, fileName string, packetLimit int) {
	handle, err := pcap.OpenLive(devName, int32(appConfig.captureSize), true,
		appConfig.CapDuration)
	if err != nil {
		log.Printf("Unable to open capture at '%s'. Error: '%v'\n", devName, err)
		return
	} else {
		log.Printf("Capturing packets at device '%s'. Capture size is %d\n", devName, appConfig.captureSize)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(filterExpr); err != nil {
		log.Printf("Unable to set filter '%s'. Error: '%v'\n", filterExpr, err)
		return
	} else {
		log.Printf("Using filter '%s'\n", filterExpr)
	}
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	fh, err := os.OpenFile(fileName+".gz", os.O_CREATE|os.O_WRONLY, 0644)
	defer func(fh *os.File) {
		err := fh.Close()
		if err != nil {
			log.Printf("Unable to close '%s'. Error: '%v'\n", fileName, err)
		}
	}(fh)
	if err != nil {
		log.Printf("Unable to open '%s'. Error: '%v'\n", fileName, err)
		return
	} else {
		log.Printf("Writing packets to the file '%s'\n", fileName)
	}
	zw := gzip.NewWriter(fh)
	zw.Name = "PCAP"
	zw.Comment = "packet capture compressed stream"
	defer func(zw *gzip.Writer) {
		if err := zw.Close(); err != nil {
			log.Println(err)
		}
	}(zw)
	// write file header
	fileHeader := pcapFileHeader{
		magic:     uint32(0xA1B23C4D), // recommended value
		verMajor:  int16(2),           // recommended value
		verMinor:  int16(4),           // recommended value
		reserved1: int32(0),           // gmt to local correction; this is always 0
		reserved2: int32(0),           // accuracy of timestamps; this is always 0
		snapLen:   int32(appConfig.captureSize & signedInt32),
		fcs:       int16(0), // magic value
		linkType:  int16(1), // ethernet
	}
	err = binary.Write(zw, binary.LittleEndian, &fileHeader)
	if err != nil {
		log.Printf(fileWriteErr, "file", err)
	}
	nPkt := 0 // captured packets counter
	waitStatus := 0
	tStart := time.Now()
	tStop := tStart
	if appConfig.CapDuration > time.Millisecond {
		tStop = tStop.Add(appConfig.CapDuration)
	} else {
		tStop = tStop.Add(time.Minute)
	}

	for waitStatus != -2 {
		if packetLimit > 0 && nPkt >= packetLimit {
			log.Printf("Packet capture limit (%d packets) reached. Stopping\n", nPkt)
			break
		}
		if time.Now().After(tStop) {
			log.Printf("Duration limit %s reached. Stopping\n", time.Now().Sub(tStart).String())
			break
		}
		var pkt gopacket.Packet = nil
		select {
		case pkt = <-packets:
			waitStatus = 1 // got packet
		case <-time.After(time.Second):
			waitStatus = -1 // got timeout
		}
		if waitStatus != 1 || pkt == nil {
			continue // no packet captured - continue
		}
		// access to captured packet via pkt
		packetBytes := pkt.Data()
		ph := pcapPacket2write{
			seconds:   int32(pkt.Metadata().Timestamp.Unix() & unsignedInt32),
			fractions: int32(pkt.Metadata().Timestamp.UnixMicro() & unsignedInt32),
			capLen:    int32(pkt.Metadata().CaptureLength & signedInt32),
			origLen:   int32(pkt.Metadata().Length & signedInt32),
		}
		err = binary.Write(zw, binary.LittleEndian, &ph)
		if err != nil {
			log.Printf(fileWriteErr, "packet", err)
			break
		}
		if pkt.Metadata().CaptureLength != len(packetBytes) {
			log.Printf("ERROR: capture length mismatch in packet %d. Expected %d, got %d\n", nPkt, pkt.Metadata().CaptureLength, len(packetBytes))
		}
		if pkt.Metadata().CaptureLength != pkt.Metadata().Length {
			log.Printf("ERROR: capture info mismatch in packet %d. Expected %d, got %d\n", nPkt, pkt.Metadata().CaptureLength, pkt.Metadata().Length)
		}
		_, err = zw.Write(packetBytes)
		if err != nil {
			log.Printf("Unable to write bytes for packet %d. Error: '%v'", nPkt, err)
		}
		nPkt++
	}
	err = zw.Flush()
	if err != nil {
		log.Printf("stream flushed with error:%v\n", err)
	} else {
		log.Printf("stream flushed\n")
	}
	err = fh.Sync()
	if err != nil {
		log.Printf("file synced with error:%v\n", err)
	} else {
		log.Printf("file synced flushed\n")
	}
}

// localAddresses - list local interfaces into string array
// skip interfaces without IP address
func localAddresses() []string {
	var ret []string = nil
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Print(fmt.Errorf("localAddresses: %v", err.Error()))
		return ret
	}
	res := make(map[string]string)
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Print(fmt.Errorf("local addresses list: %v", err.Error()))
			continue
		}
		if (i.Flags & net.FlagLoopback) == net.FlagLoopback {
			continue // skip loopback interfaces
		}
		// for any interface with IPv4 of IPv6 addresses
		for _, a := range addrs {
			res[i.Name] = a.String()
			if appConfig.listInterfaces {
				log.Printf("%v", i)
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
	}
	return ret
}

func main() {
	// command ine parameters
	flag.StringVar(&appConfig.interfaceName, "interface", sEmpty, "Network interface name (first interface with IP address)")
	flag.StringVar(&appConfig.interfaceName, "i", sEmpty, "Network interface name (first interface with IP address)")
	flag.StringVar(&appConfig.filter, "filter", defFilter, "Packet filter expression")
	flag.StringVar(&appConfig.filter, "f", defFilter, "Packet filter expression")
	flag.StringVar(&appConfig.fileName, "output", defFile, "Output file name")
	flag.StringVar(&appConfig.fileName, "o", defFile, "Output file name")
	flag.IntVar(&appConfig.maxPacketCount, "count", defPacketCount, "Captured packet count limit (-1 equals limitless)")
	flag.IntVar(&appConfig.maxPacketCount, "c", defPacketCount, "Captured packet count limit (-1 equals limitless)")
	flag.IntVar(&appConfig.captureSize, "snap_len", defaultSnapLen, "Capture buffer size")
	flag.IntVar(&appConfig.captureSize, "s", defaultSnapLen, "Capture buffer size")
	flag.DurationVar(&appConfig.CapDuration, "duration", pcap.BlockForever, "Capture duration limit (limitless by default)")
	flag.DurationVar(&appConfig.CapDuration, "d", pcap.BlockForever, "Capture duration limit (limitless by default)")
	flag.BoolVar(&appConfig.listInterfaces, "list", false, "list of available interfaces")
	flag.BoolVar(&appConfig.listInterfaces, "l", false, "list of available interfaces")
	flag.Parse()

	if appConfig.interfaceName == sEmpty {
		// no interface specified - list all
		interfaces := localAddresses()
		if appConfig.listInterfaces {
			return
		}
		if interfaces != nil {
			// and get the first
			appConfig.interfaceName = interfaces[0]
		}
	}
	if appConfig.filter == sEmpty {
		appConfig.filter = defFilter
	}
	getPacketz(appConfig.interfaceName, appConfig.filter, appConfig.fileName, appConfig.maxPacketCount)

}
