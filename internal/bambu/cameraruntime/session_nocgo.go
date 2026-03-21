//go:build !cgo

package cameraruntime

import "errors"

type nativeSession struct{}

func openNativeSession(pluginLibraryPath string, host string, accessCode string) (*nativeSession, error) {
	return nil, errors.New("bambu native runtime requires cgo")
}

func (s *nativeSession) ReadChunk() ([]byte, error) {
	return nil, errors.New("bambu native runtime requires cgo")
}

func (s *nativeSession) Close() {}
