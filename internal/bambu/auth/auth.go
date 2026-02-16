package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrMFARequired = errors.New("bambu_mfa_required")
var ErrInvalidCredentials = errors.New("bambu_invalid_credentials")
var ErrTemporary = errors.New("bambu_temporary_error")

type LoginRequest struct {
	Username string
	Password string
	MFACode  string
}

type RefreshRequest struct {
	RefreshToken string
}

type Session struct {
	AccessToken        string
	RefreshToken       string
	ExpiresAt          time.Time
	MaskedEmail        string
	MaskedPhone        string
	AccountDisplayName string
}

type Provider interface {
	Login(ctx context.Context, req LoginRequest) (Session, error)
	Refresh(ctx context.Context, req RefreshRequest) (Session, error)
}

type Error struct {
	Kind    error
	Message string
}

func (e *Error) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		if e.Kind != nil {
			return e.Kind.Error()
		}
		return "bambu auth error"
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Kind
}
