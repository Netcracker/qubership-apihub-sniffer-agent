package entities

import "strconv"

type EndPoint struct {
	Address    string
	Port       int
	Registered bool
}

func EndPointToString(endPoint EndPoint) string {
	return endPoint.Address + ":" + strconv.Itoa(endPoint.Port)
}
