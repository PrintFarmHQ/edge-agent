//go:build !cgo

package cameraruntime

import "errors"

type nativeSession struct{}
type nativeControlSession struct{}

func openNativeSession(pluginLibraryPath string, host string, accessCode string) (*nativeSession, error) {
	return nil, errors.New("bambu native runtime requires cgo")
}

func (s *nativeSession) ReadChunk() ([]byte, error) {
	return nil, errors.New("bambu native runtime requires cgo")
}

func (s *nativeSession) Close() {}

func openNativeControlSession(pluginLibraryPath string, host string, accessCode string) (*nativeControlSession, error) {
	return nil, errors.New("bambu native runtime requires cgo")
}

func (s *nativeControlSession) SendMessage(message []byte) error {
	return errors.New("bambu native runtime requires cgo")
}

func (s *nativeControlSession) ReadMessage() ([]byte, error) {
	return nil, errors.New("bambu native runtime requires cgo")
}

func (s *nativeControlSession) Close() {}
