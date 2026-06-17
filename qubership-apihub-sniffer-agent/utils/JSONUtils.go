package utils

import "encoding/json"

func MarshalToJSON(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}
