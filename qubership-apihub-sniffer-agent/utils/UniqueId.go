package utils

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// MakeUniqueId
// makes UUID
func MakeUniqueId() string {
	defer func() {
		if x := recover(); x != nil {
			log.Error("make unique Id in recover, caught error====================", x)
		}
	}()
	return uuid.NewString()
}
