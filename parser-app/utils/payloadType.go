package utils

import (
	"compress/gzip"
	"io"
	"regexp"
)

type PayloadType int

const (
	PTNotHttp PayloadType = iota
	PTHttpReq
	PTHttpResp
	PTHttp
)

type DecodeFeedback struct {
}

func (df *DecodeFeedback) SetTruncated() {

}

func DetectHttp(payLoad []byte) PayloadType {
	//utils.DumpBytes("isHTTP", payLoad)
	var reqRe = regexp.MustCompile(`(?m)(\w+)\s+(\S+)\s+HTTP/\d+\.\d+`)
	var respRe = regexp.MustCompile(`(?m)HTTP/\d+\.\d+\s+(\d+\s+[\w\s_.]+)`)
	if reqRe.Find(payLoad) != nil {
		return PTHttpReq
	}
	if respRe.Find(payLoad) != nil {
		return PTHttpResp
	}
	httpB := []byte("HTTP")
	pos := 0
	pl := len(payLoad)
	hl := len(httpB) - 1
	bFound := false
	for pos < pl {
		for i := 0; i <= hl && pos < pl; i++ {
			if payLoad[pos] == httpB[i] {
				pos++
				if i == hl {
					bFound = true
				}
			} else {
				pos++
				break
			}
		}
		if bFound {
			break
		}
	}
	if bFound {
		return PTHttp
	}
	return PTNotHttp
}

func BodyToString(Body io.Reader, Uncompressed bool) ([]byte, int, error) {
	var (
		body []byte
		n          = -1
		err  error = nil
	)
	if Uncompressed {
		body, err = io.ReadAll(Body)
	} else {
		zr, err1 := gzip.NewReader(Body)
		if err1 == nil {
			body, err = io.ReadAll(zr)
		} else {
			err = err1
		}
	}
	if err == nil {
		n = len(body)
	}
	return body, n, err
}
