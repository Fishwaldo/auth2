package webauthn

import (
	"fmt"
	"github.com/Fishwaldo/auth2/internal/errors"
)

var (
	// ErrInvalidChallenge is returned when a challenge is invalid or expired
	ErrInvalidChallenge = errors.New("invalid or expired challenge")
	
	// ErrCredentialNotFound is returned when a credential is not found
	ErrCredentialNotFound = errors.New("credential not found")
	
	// ErrInvalidCredential is returned when a credential is invalid
	ErrInvalidCredential = errors.New("invalid credential")
	
	// ErrUserNotFound is returned when a user is not found
	ErrUserNotFound = errors.New("user not found")
	
	// ErrRegistrationFailed is returned when registration fails
	ErrRegistrationFailed = errors.New("registration failed")
	
	// ErrAuthenticationFailed is returned when authentication fails
	ErrAuthenticationFailed = errors.New("authentication failed")
	
	// ErrInvalidOrigin is returned when the origin is not allowed
	ErrInvalidOrigin = errors.New("invalid origin")
	
	// ErrCounterError is returned when the counter validation fails
	ErrCounterError = errors.New("counter validation failed")
	
	// ErrInvalidUserVerification is returned when user verification fails
	ErrInvalidUserVerification = errors.New("user verification failed")
	
	// ErrDuplicateCredential is returned when trying to register a duplicate credential
	ErrDuplicateCredential = errors.New("credential already registered")
)

// ErrInvalidConfig creates a configuration error
func ErrInvalidConfig(msg string) error {
	return fmt.Errorf("invalid webauthn config: %s", msg)
}

// WrapError wraps an error with additional context
func WrapError(err error, msg string) error {
	return fmt.Errorf("%s: %w", msg, err)
}