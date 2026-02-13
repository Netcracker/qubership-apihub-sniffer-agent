package entities

import (
	"crypto/md5"
	"fmt"
)

type HttpHeaderItem struct {
	Key   string
	Value string
	Id    string
}

func ComputeId(key, value string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(key+value)))
}

//func NewHeader(key, value string) HttpHeaderItem {
//	return HttpHeaderItem{Key: key, Value: value, Id: ComputeId(key, value)}
//}
