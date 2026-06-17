package view

import (
	"crypto/md5"
	"fmt"
	"strings"
)

const (
	printFormat  = "%d%s%d%d"
	hexMd5Format = "%x"
)

// CaptureRequest
// received capture request
type CaptureRequest struct {
	Filter        string   `json:"filter,omitempty"`
	Id            string   `json:"id,omitempty"`
	PacketCount   int      `json:"packet_count,omitempty"`
	Duration      string   `json:"duration,omitempty"`
	FileSize      int      `json:"file_size,omitempty"`
	DateAndTime   string   `json:"time_stamp,omitempty"`
	CheckSum      string   `json:"check_sum,omitempty"`
	Namespaces    []string `json:"namespaces,omitempty"`
	CaptureDevice string   `json:"capture_device,omitempty"`
	SnapshotLen   int      `json:"snapshot_len,omitempty"`
}

// getStringForSum
// get unified string from stored data to compute checksum
func getStringForSum(req CaptureRequest, apiKey string) string {
	return apiKey + req.Filter + req.Id +
		fmt.Sprintf(printFormat, req.PacketCount, req.Duration, req.FileSize, req.SnapshotLen) +
		req.DateAndTime + strings.Join(req.Namespaces, ArrayJoinSeparator) + req.CaptureDevice
}

// GetRequestChecksum
// compute checksum on capture request
func GetRequestChecksum(req CaptureRequest, apiKey, internalKey string) string {
	return fmt.Sprintf(hexMd5Format, md5.Sum([]byte(getStringForSum(req, apiKey)+internalKey)))
}
