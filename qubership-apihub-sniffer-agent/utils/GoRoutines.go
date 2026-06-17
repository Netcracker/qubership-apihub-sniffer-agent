package utils

import (
	"runtime/debug"

	log "github.com/sirupsen/logrus"
)

// noPanicFunc
// turns panic into an error
type noPanicFunc func()

// noPanicFuncP
// turns panic into an error, accepts parameter
type noPanicFuncP func(param interface{})

// run
// runs and recovers function
func (f noPanicFunc) run() {
	defer internalRecover()
	f()
}

// runWithParams
// runs and recovers function with parameter
func (f noPanicFuncP) runWithParams(param interface{}) {
	defer internalRecover()
	f(param)
}

// SafeAsync
// suppress panics within goroutine
func SafeAsync(function noPanicFunc) {
	go function.run()
}

// SafeRun
// suppress panics
func SafeRun(function noPanicFunc) {
	function.run()
}

// SafeRunWithParam
// suppress panics
func SafeRunWithParam(function noPanicFuncP, param interface{}) {
	function.runWithParams(param)
}

// SafeAsyncWithParam
// pass parameter into goroutine and suppress panics
func SafeAsyncWithParam(function noPanicFuncP, param interface{}) {
	go function.runWithParams(param)
}

// internalRecover
// panic recovery
func internalRecover() {
	if err := recover(); err != nil {
		log.Errorf("Request failed with panic: %v", err)
		log.Tracef("Stacktrace: %v", string(debug.Stack()))
		debug.PrintStack()
		return
	}
}
