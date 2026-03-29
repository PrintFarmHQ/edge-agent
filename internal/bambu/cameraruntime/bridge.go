//go:build cgo && (darwin || linux || windows)

package cameraruntime

/*
#cgo darwin CFLAGS: -std=c11
#cgo linux CFLAGS: -std=c11
#cgo windows CFLAGS: -std=c11

#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

type nativeSession struct {
	handle *C.PFHBambuRuntime
}

type nativeControlSession struct {
	handle *C.PFHBambuRuntime
}

func openNativeSession(pluginLibraryPath string, host string, accessCode string) (*nativeSession, error) {
	cLib := C.CString(pluginLibraryPath)
	cHost := C.CString(host)
	cAccessCode := C.CString(accessCode)
	defer C.free(unsafe.Pointer(cLib))
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cAccessCode))

	var runtimeHandle *C.PFHBambuRuntime
	var errMsg *C.char
	result := C.pfh_bambu_runtime_open(cLib, cHost, cAccessCode, &runtimeHandle, &errMsg)
	if result != 0 {
		return nil, consumeBridgeError(errMsg)
	}
	if runtimeHandle == nil {
		return nil, errors.New("bambu native runtime returned a nil session")
	}
	return &nativeSession{handle: runtimeHandle}, nil
}

func (s *nativeSession) ReadChunk() ([]byte, error) {
	if s == nil || s.handle == nil {
		return nil, errors.New("bambu native session is not open")
	}
	var data *C.uchar
	var size C.int
	var status C.int
	var errMsg *C.char
	result := C.pfh_bambu_runtime_read_sample(s.handle, &data, &size, &status, &errMsg)
	defer func() {
		if data != nil {
			C.pfh_bambu_runtime_free_bytes(data)
		}
	}()
	if result != 0 {
		return nil, consumeBridgeError(errMsg)
	}
	if status == C.PFHBambuStatusWouldBlock {
		return nil, errWouldBlock
	}
	if status == C.PFHBambuStatusStreamEnd {
		return nil, errStreamEnd
	}
	if data == nil || size <= 0 {
		return nil, nil
	}
	return C.GoBytes(unsafe.Pointer(data), size), nil
}

func (s *nativeSession) Close() {
	if s == nil || s.handle == nil {
		return
	}
	C.pfh_bambu_runtime_close(s.handle)
	s.handle = nil
}

func openNativeControlSession(pluginLibraryPath string, host string, accessCode string) (*nativeControlSession, error) {
	cLib := C.CString(pluginLibraryPath)
	cHost := C.CString(host)
	cAccessCode := C.CString(accessCode)
	defer C.free(unsafe.Pointer(cLib))
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cAccessCode))

	var runtimeHandle *C.PFHBambuRuntime
	var errMsg *C.char
	result := C.pfh_bambu_control_open(cLib, cHost, cAccessCode, &runtimeHandle, &errMsg)
	if result != 0 {
		return nil, consumeBridgeError(errMsg)
	}
	if runtimeHandle == nil {
		return nil, errors.New("bambu native runtime returned a nil control session")
	}
	return &nativeControlSession{handle: runtimeHandle}, nil
}

func (s *nativeControlSession) SendMessage(message []byte) error {
	if s == nil || s.handle == nil {
		return errors.New("bambu native control session is not open")
	}
	if len(message) == 0 {
		return errors.New("bambu native control message is empty")
	}
	var errMsg *C.char
	result := C.pfh_bambu_control_send_message(
		s.handle,
		(*C.uchar)(unsafe.Pointer(&message[0])),
		C.int(len(message)),
		&errMsg,
	)
	if result != 0 {
		return consumeBridgeError(errMsg)
	}
	return nil
}

func (s *nativeControlSession) ReadMessage() ([]byte, error) {
	if s == nil || s.handle == nil {
		return nil, errors.New("bambu native control session is not open")
	}
	var data *C.uchar
	var size C.int
	var status C.int
	var errMsg *C.char
	result := C.pfh_bambu_control_read_message(s.handle, &data, &size, &status, &errMsg)
	defer func() {
		if data != nil {
			C.pfh_bambu_runtime_free_bytes(data)
		}
	}()
	if result != 0 {
		return nil, consumeBridgeError(errMsg)
	}
	if status == C.PFHBambuStatusWouldBlock {
		return nil, errWouldBlock
	}
	if status == C.PFHBambuStatusStreamEnd {
		return nil, errStreamEnd
	}
	if data == nil || size <= 0 {
		return nil, nil
	}
	return C.GoBytes(unsafe.Pointer(data), size), nil
}

func (s *nativeControlSession) Close() {
	if s == nil || s.handle == nil {
		return
	}
	C.pfh_bambu_runtime_close(s.handle)
	s.handle = nil
}

func consumeBridgeError(errMsg *C.char) error {
	if errMsg == nil {
		return errors.New("bambu native runtime failed without an error message")
	}
	defer C.pfh_bambu_runtime_free_string(errMsg)
	return errors.New(C.GoString(errMsg))
}
