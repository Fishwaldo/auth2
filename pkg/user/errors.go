package user

import "errors"

// Common user-related errors
var (
	// ErrUserNotFound is returned when a user cannot be found
	ErrUserNotFound = errors.New("user not found")
	
	// ErrInvalidCredentials is returned when credentials are invalid
	ErrInvalidCredentials = errors.New("invalid credentials")
	
	// ErrUserDisabled is returned when a user account is disabled
	ErrUserDisabled = errors.New("user account is disabled")
	
	// ErrUserLocked is returned when a user account is locked
	ErrUserLocked = errors.New("user account is locked")
	
	// ErrEmailNotVerified is returned when a user's email is not verified
	ErrEmailNotVerified = errors.New("email not verified")
	
	// ErrPasswordChangeRequired is returned when a user must change their password
	ErrPasswordChangeRequired = errors.New("password change required")
	
	// ErrDuplicateUser is returned when a user with the same unique identifier already exists
	ErrDuplicateUser = errors.New("user already exists")
)

// UserError is defined in user.go and is a more detailed error type
// with code, message, and optional cause