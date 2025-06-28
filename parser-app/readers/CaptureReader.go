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

package readers

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"parser-app/Cache"
	"parser-app/entities"
	"parser-app/utils"
	"path"
	"regexp"
	"strings"
)

type CaptureReader interface {
	ReadCapture(captureId string, workDir string) error
}

func NewCaptureReader(headers Cache.HttpHeadersCache, packets Cache.PacketCache, peers Cache.PeersCache) CaptureReader {
	return &captureReaderImpl{
		headers:       headers,
		packets:       packets,
		peers:         peers,
		captureId:     "",
		addrToService: make(map[string]string),
	}
}

type captureReaderImpl struct {
	headers       Cache.HttpHeadersCache
	packets       Cache.PacketCache
	peers         Cache.PeersCache
	captureId     string
	addrToService map[string]string
}

func (cr *captureReaderImpl) ReadCapture(captureId string, workDir string) error {
	fileInfo, err := os.Lstat(workDir)
	if err != nil {
		log.Errorf("unable to get info for work dir %s : %v", workDir, err.Error())
		return err
	}
	if fileInfo == nil {
		log.Errorf("unable to get info for work dir %s : file info is nil", workDir)
		return nil
	}
	if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
		realDir, err := os.Readlink(workDir)
		if err != nil {
			log.Errorf("unable to read link for work dir %s : %v", workDir, err.Error())
			return err
		}
		fileInfo, err := os.Lstat(realDir)
		if err != nil {
			log.Errorf("unable to get info for work dir %s : %v", workDir, err.Error())
			return err
		}
		if fileInfo.Mode()&os.ModeDir != os.ModeDir {
			log.Errorf("unable to work with not dir %s", realDir)
			return err
		}
		workDir = realDir
	}
	items, err := os.ReadDir(workDir)
	if err != nil {
		log.Fatalf("unable to read dir %s : %v", workDir, err.Error())
	}
	// fill service names
	for _, item := range items {
		if item.IsDir() {
			continue
		}
		if !strings.HasPrefix(item.Name(), captureId) {
			continue
		}
		inputFilename := path.Join(workDir, item.Name())
		if strings.HasSuffix(inputFilename, ".txt.gz") || strings.HasSuffix(inputFilename, ".txt") {
			// service name list
			fh, err := os.Open(inputFilename)
			if err != nil {
				log.Errorf("unable to open file. Error: %v", err)
				continue
			}
			if path.Ext(inputFilename) == ".gz" {
				zr, err := gzip.NewReader(fh)
				if zr == nil || err != nil {
					if err != nil {
						log.Errorf("unable to uncompress file %s. Error: %v", item.Name(), err)
					} else {
						log.Errorf("unable to uncompress file %s", item.Name())
					}
					continue
				}
				cr.readCaptureServiceMap(zr)
				err = zr.Close()
				if err != nil {
					log.Errorf("unable to close compressed file %s. Error: %v", item.Name(), err)
				}
			} else {
				cr.readCaptureServiceMap(fh)
			}
			err = fh.Close()
			if err != nil {
				log.Errorf("unable to close file '%s'. Error: %v", item.Name(), err)
			}
		}
	}
	// read captures
	for _, item := range items {
		if item.IsDir() {
			continue
		}
		if !strings.HasPrefix(item.Name(), captureId) {
			continue
		}
		inputFilename := path.Join(workDir, item.Name())
		if strings.HasSuffix(inputFilename, ".pcap.gz") || strings.HasSuffix(inputFilename, ".pcap") {
			fh, err := os.Open(inputFilename)
			if err != nil {
				log.Errorf("unable to open file. Error: %v", err)
				continue
			}
			if path.Ext(inputFilename) == ".gz" {
				zr, err := gzip.NewReader(fh)
				if zr == nil || err != nil {
					if err != nil {
						log.Errorf("unable to uncompress file %s. Error: %v", item.Name(), err)
					} else {
						log.Errorf("unable to uncompress file %s", item.Name())
					}
					continue
				}
				tmpFileName := inputFilename + ".tmp"
				fth, err := os.Create(tmpFileName)
				if err != nil {
					log.Errorf("unable to create intermediate file '%s'. Error: %v", tmpFileName, err)
				} else {
					if _, err := io.Copy(fth, zr); err != nil {
						log.Errorf("unable to write uncompressed data. error: %v", err)
					}
					err = fth.Close()
					if err != nil {
						log.Errorf("unable to close intermedate file '%s'. Error: %v", tmpFileName, err)
					}
					err = cr.readPackets(tmpFileName)
				}
				err = zr.Close()
				if err != nil {
					log.Errorf("unable to close compressed file %s. Error: %v", item.Name(), err)
				}

			} else {
				err = cr.readPackets(inputFilename)
			}
			err = fh.Close()
			if err != nil {
				log.Errorf("unable to close file '%s'. Error: %v", item.Name(), err)
			}
		}
	}
	return nil
}

func (cr *captureReaderImpl) readCaptureServiceMap(fh io.Reader) {
	scanner := bufio.NewScanner(fh)
	if scanner == nil {
		return
	}
	var reqRe = regexp.MustCompile(`^([a-f\d\.\:]+)\s+(.+)\s*$`)
	for scanner.Scan() {
		ms := reqRe.FindStringSubmatch(scanner.Text())
		if ms != nil {
			cr.addrToService[ms[1]] = ms[2]
		}
	}
}

type IPversion int

const IPvUnknown IPversion = 0
const IPv4 = 4
const IPv6 = 6

type IPPacket struct {
	version     IPversion
	SrcIP       string
	DstIP       string
	TCP         []byte
	TCPExpected bool
}

func incErrorCount(m map[string]int, name string) {
	val, ok := m[name]
	if !ok {
		m[name] = 1
	} else {
		m[name] = val + 1
	}
}

func decodeIp(payload []byte, ipv6 bool, errCount map[string]int, i int) (IPPacket, error) {
	var err error = nil
	ip := IPPacket{
		version:     IPvUnknown,
		SrcIP:       "",
		DstIP:       "",
		TCP:         nil,
		TCPExpected: false,
	}
	df := utils.DecodeFeedback{}
	if ipv6 {
		ipv6 := layers.IPv6{}
		err = ipv6.DecodeFromBytes(payload, &df)
		if err != nil {
			log.Debugf("unable to decode IPv4 packet %d. Error: %v\n", i, err)
			incErrorCount(errCount, "ipv4fail")
		}
		ip.SrcIP = ipv6.SrcIP.String()
		ip.DstIP = ipv6.DstIP.String()
		ip.TCP = ipv6.Payload
		ip.version = IPv6
		ip.TCPExpected = true
	} else {
		ipv4 := layers.IPv4{}
		err = ipv4.DecodeFromBytes(payload, &df)
		if err != nil {
			log.Debugf("unable to decode IPv4 packet %d. Error: %v\n", i, err)
			incErrorCount(errCount, "ipv4fail")
		}
		ip.SrcIP = ipv4.SrcIP.String()
		ip.DstIP = ipv4.DstIP.String()
		ip.version = IPv4
		if ipv4.Protocol == layers.IPProtocolTCP {
			ip.TCP = ipv4.Payload
			ip.TCPExpected = true
		}
	}
	return ip, err
}

func (cr *captureReaderImpl) readPackets(fileName string) error {
	log.Printf("working on %s", fileName)
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Printf("unable to open capture file %s. Error: %v", fileName, err)
		return err
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := -1
	parsedPackets := 0
	parsedIPPackets := 0
	parsedHTTPPackets := 0
	streams := make(map[uint32]entities.ParsedPacket)
	df := utils.DecodeFeedback{}
	errCount := make(map[string]int)
	for packet := range packetSource.Packets() {
		i++
		ll := 0
		ls1 := ""
		eld := packet.Layer(layers.LayerTypeEthernet)
		ip := IPPacket{
			SrcIP: "",
			DstIP: "",
			TCP:   nil,
		}
		if eld != nil {
			eth := layers.Ethernet{}
			err = eth.DecodeFromBytes(packet.Data(), &df)
			if err != nil {
				incErrorCount(errCount, "eth_parse")
				continue
			}
			if eth.Payload == nil {
				incErrorCount(errCount, "eth_payload")
				continue
			}
			if eth.EthernetType == layers.EthernetTypeIPv4 || eth.EthernetType == layers.EthernetTypeIPv6 {
				ip, err = decodeIp(eth.Payload, false, errCount, i)
				if err != nil {
					ip, err = decodeIp(eth.Payload, false, errCount, i)
					if err != nil {
						incErrorCount(errCount, "ipv6fail")
						continue // not an IP packet
					} else {
						incErrorCount(errCount, "ipv4fail") // IPv6
					}
				}
			} else {
				incErrorCount(errCount, "not_an_EthernetTypeIP")
				continue
			}
		}
		if ip.TCP == nil {
			incErrorCount(errCount, "not_an_ip_packet2")
			continue // not an IPv6/IPv6 packet
		}
		peers := make([]entities.EndPoint, 2)
		sname := ""
		dname := ""
		sname, peers[entities.SourcePeer].Registered = cr.addrToService[ip.SrcIP]
		dname, peers[entities.DestPeer].Registered = cr.addrToService[ip.DstIP]
		//if !peers[entities.SourcePeer].Registered && !peers[entities.DestPeer].Registered {
		//	log.Warnf("both addresses (%s and %s) are not known", ip.SrcIP, ip.DstIP)
		//	incErrorCount(errCount, "unknown_ips")
		//	continue // both addresses are not known
		//}
		parsedIPPackets++
		tcp := layers.TCP{}
		err = tcp.DecodeFromBytes(ip.TCP, &df)
		if err != nil {
			log.Errorf("unable to decode TCP packet %d. Error: %v\n", i, err)
			incErrorCount(errCount, "tcp_decode_failure")
			continue // not a TCP packet
		}
		parsedPackets++
		peers[entities.SourcePeer].Address = ip.SrcIP
		peers[entities.SourcePeer].Port = int(tcp.SrcPort)
		peers[entities.DestPeer].Address = ip.DstIP
		peers[entities.DestPeer].Port = int(tcp.DstPort)
		headers := make(map[string]string)
		tcpPayLoad := tcp.Payload
		reqMethod := ""
		reqPath := ""
		if tcpPayLoad != nil {
			pt := utils.DetectHttp(tcpPayLoad)
			switch pt {
			case utils.PTHttpReq:
				{
					parsedHTTPPackets++
					br := bytes.NewReader(tcpPayLoad)
					req, err := http.ReadRequest(bufio.NewReader(br))
					if err == nil && req != nil {
						// headers
						for hname, hvalue := range req.Header {
							hcvalue := ""
							for _, hvr := range hvalue {
								hcvalue += hvr
							}
							if hcvalue != "" {
								headers[hname] = hcvalue
							}
						}
						// request!
						reqMethod = req.Method
						reqPath = req.URL.Path
						body, n, err := utils.BodyToString(req.Body, true)
						if err == nil {
							ls1 = fmt.Sprintf("%s -> %s => %s: '%s'", req.Method, req.RequestURI, req.Host, string(body))
						} else {
							ls1 = fmt.Sprintf("%s -> %s => %s (%d:%v)", req.Method, req.RequestURI, req.Host, n, err)
						}
					} else {
						if err != nil {
							incErrorCount(errCount, "request_body_failure")
						}
					}
				}
			case utils.PTHttpResp:
				{
					parsedHTTPPackets++
					br := bytes.NewReader(tcpPayLoad)
					resp, err := http.ReadResponse(bufio.NewReader(br), nil)
					if err == nil && resp != nil {
						// headers
						for hname, hvalue := range resp.Header {
							hcvalue := strings.Builder{}
							for _, hvr := range hvalue {
								n, e := hcvalue.WriteString(hvr)
								if e != nil {
									log.Printf("unable to decode HTTP response header %d. Error: %v\n", n, e)
									incErrorCount(errCount, "http_header_decode_failure")
									break
								}
							}
							if hcvalue.Len() > 0 {
								headers[hname] = hcvalue.String()
							}
						}
						// response!
						body, n, err := utils.BodyToString(resp.Body, resp.Uncompressed)
						if err == nil {
							ls1 = fmt.Sprintf("%s -> %d:'%s'", resp.Status, resp.ContentLength, string(body))
						} else {
							ls1 = fmt.Sprintf("%s -> length %d: error %v", resp.Status, n, err)
						}
					} else {
						if err != nil {
							incErrorCount(errCount, "response_body_decode_failure")
						}
					}
				}
			case utils.PTHttp:
				ls1 = string(tcpPayLoad)
			case utils.PTNotHttp:
				log.Debugf("not a HTTP packet %d\n", i)
			default:
				log.Debug("unhandled default case")
			}
			ll = len(ls1)
			if ll < 1 {
				incErrorCount(errCount, "no_data")
				continue
			}
			p2s := entities.ParsedPacket{
				Peers:         nil,
				Timestamp:     packet.Metadata().Timestamp,
				SeqNo:         int(tcp.Seq),
				AckNo:         int(tcp.Ack),
				Payload:       tcpPayLoad,
				StrPayload:    ls1,
				RequestUri:    reqPath,
				RequestMethod: reqMethod,
			}
			if stream, found := streams[tcp.Seq]; found {
				//p2s.StreamId = int(tcp.Seq)
				log.Printf("stream %x (%s:%d -> %s:%d) found\n",
					p2s.SeqNo,
					stream.Peers[entities.SourcePeer].Address, stream.Peers[entities.SourcePeer].Port,
					stream.Peers[entities.DestPeer].Address, stream.Peers[entities.DestPeer].Port)
				delete(streams, tcp.Seq)
			} else {
				//p2s.StreamId = int(tcp.Ack)
				log.Printf("candidate %x (%s:%d -> %s:%d) found\n",
					p2s.AckNo,
					peers[entities.SourcePeer].Address, peers[entities.SourcePeer].Port,
					peers[entities.DestPeer].Address, peers[entities.DestPeer].Port)
			}
			p2s.Headers = headers
			p2s.Peers = peers
			if peers[entities.SourcePeer].Registered {
				p2s.ServiceName = sname
			} else {
				if peers[entities.DestPeer].Registered {
					p2s.ServiceName = dname
				}
			}
			err = cr.packets.StorePacket(p2s, cr.headers)
		}
		if ll > 0 {
			log.Printf("%05d : > %d(%s)\n", i+1, ll, ls1)
		}
		i++
	}
	log.Errorf("Error counters are:")
	for x := range errCount {
		log.Errorf("%s\t%d", x, errCount[x])
	}
	log.Printf("Total packets: %d, parsed: %d, ip:%d, http:%d", i, parsedPackets, parsedIPPackets, parsedHTTPPackets)
	return nil
}
