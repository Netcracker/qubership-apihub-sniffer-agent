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
