package view

import (
	"crypto/md5"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetRequestChecksum(t *testing.T) {
	req := CaptureRequest{
		Filter:      "123",
		Id:          "456",
		PacketCount: 1,
		Duration:    "1m59s",
		FileSize:    2,
		DateAndTime: EmptyString,
		CheckSum:    EmptyString,
		Namespace:   EmptyString,
	}
	apiKey := "789"
	s1 := getStringForSum(req, apiKey)
	s2 := apiKey + req.Filter + req.Id + fmt.Sprintf(printFormat, req.PacketCount, req.Duration, req.FileSize, req.SnapshotLen) + req.DateAndTime + req.Namespace
	assert.Equal(t, s1, s2, "getStringForSum")
	internalKey := "abc"
	sum1 := fmt.Sprintf(hexMd5Format, md5.Sum([]byte(getStringForSum(req, apiKey)+internalKey)))
	sum2 := fmt.Sprintf(hexMd5Format, md5.Sum([]byte(s2+internalKey)))
	assert.Equal(t, sum1, sum2, "direct md5")
	sum3 := GetRequestChecksum(req, apiKey, internalKey)
	assert.Equal(t, sum3, sum1, "getRequestChecksum")
}
