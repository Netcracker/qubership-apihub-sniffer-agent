package view

import "time"

const (
	EmptyString  = ""
	GzipSuffix   = ".gz"
	ApiKeyHeader = "api-key"
	// DefaultFileDataSize packet data size (without header) stored in a single file
	DefaultFileDataSize = 681574400 // 650M per file by default
	// DefaultCaptureDuration default capture duration instead of pcap.BlockForever
	DefaultCaptureDuration = time.Second * 60
	MinCaptureDuration     = time.Second * 15
	// CaptureInterfaceAny a synonym for all interfaces at the host
	CaptureInterfaceAny = "any"
	// CaptureInterfaceDetect use the first interface with an IPv4 or IPv6 address
	CaptureInterfaceDetect = "auto"
	// DefaultSnapLenBytes The same default as tcpdump.
	DefaultSnapLenBytes = 256 * 1024
	// ArrayJoinSeparator a separator to use with strings.Join
	ArrayJoinSeparator = ","
	// FilterMaxLength a limit to capture filter length. Sniffer agent will fail when filter bigger than this size
	FilterMaxLength = 64 * 1024
)
