package cameraruntime

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	errWouldBlock = errors.New("bambu native runtime would block")
	errStreamEnd  = errors.New("bambu native runtime stream ended")
)

type Session interface {
	ReadChunk() ([]byte, error)
	Close()
}

func OpenSession(handle Handle) (Session, error) {
	return openNativeSession(handle.PluginLibraryPath, handle.Host, handle.AccessCode)
}

func ReadJPEGFrame(ctx context.Context, session Session) ([]byte, error) {
	reader := &sessionChunkReader{
		ctx:     ctx,
		session: session,
	}
	return readNextJPEGFrame(reader)
}

func readNextJPEGFrame(reader io.Reader) ([]byte, error) {
	buffer := make([]byte, 0, 128*1024)
	chunk := make([]byte, 4096)
	prev := byte(0x00)
	inFrame := false

	for {
		n, err := reader.Read(chunk)
		for i := 0; i < n; i++ {
			current := chunk[i]
			if !inFrame {
				if prev == 0xFF && current == 0xD8 {
					inFrame = true
					buffer = append(buffer[:0], 0xFF, 0xD8)
				}
			} else {
				buffer = append(buffer, current)
				if prev == 0xFF && current == 0xD9 {
					return append([]byte(nil), buffer...), nil
				}
			}
			prev = current
		}
		if err != nil {
			if len(buffer) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

type sessionChunkReader struct {
	ctx     context.Context
	session Session
	pending []byte
}

func (r *sessionChunkReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if r.ctx != nil {
			select {
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			default:
			}
		}

		chunk, err := r.session.ReadChunk()
		switch {
		case err == nil:
			if len(chunk) == 0 {
				continue
			}
			r.pending = chunk
		case errors.Is(err, errWouldBlock):
			if r.ctx != nil {
				select {
				case <-r.ctx.Done():
					return 0, r.ctx.Err()
				case <-time.After(100 * time.Millisecond):
				}
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		case errors.Is(err, errStreamEnd):
			return 0, io.EOF
		default:
			return 0, err
		}
	}

	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
