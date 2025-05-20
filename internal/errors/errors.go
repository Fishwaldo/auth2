package errors

import (
	"errors"
	"fmt"
)

// Standard errors in the auth2 package
var (
	// General errors
	ErrInternal         = errors.New("internal error")
	ErrNotImplemented   = errors.New("not implemented")
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrInvalidOperation = errors.New("invalid operation")
	
	// Authentication errors
	ErrAuthFailed        = errors.New("authentication failed")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound      = errors.New("user not found")
	ErrUserDisabled      = errors.New("user account is disabled")
	ErrUserLocked        = errors.New("user account is locked")
	
	// MFA errors
	ErrMFARequired      = errors.New("multi-factor authentication required")
	ErrMFAFailed        = errors.New("multi-factor authentication failed")
	ErrMFANotEnabled    = errors.New("multi-factor authentication not enabled")
	ErrInvalidMFACode   = errors.New("invalid multi-factor authentication code")
	
	// Session errors
	ErrSessionExpired   = errors.New("session has expired")
	ErrInvalidSession   = errors.New("invalid session")
	ErrSessionNotFound  = errors.New("session not found")
	
	// Token errors
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token has expired")
	
	// Permission errors
	ErrPermissionDenied = errors.New("permission denied")
	ErrRoleNotFound     = errors.New("role not found")
	
	// Rate limiting errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	
	// Plugin errors
	ErrPluginNotFound   = errors.New("plugin not found")
	ErrIncompatiblePlugin = errors.New("incompatible plugin")
)

// AuthError represents an authentication-related error
type AuthError struct {
	Err       error
	Code      string
	UserID    string
	Reason    string
	Temporary bool
}

// Error implements the error interface
func (e *AuthError) Error() string {
	if e.UserID != "" {
		return fmt.Sprintf("[%s] %s: %s (user: %s)", e.Code, e.Err.Error(), e.Reason, e.UserID)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Err.Error(), e.Reason)
}

// Unwrap returns the wrapped error
func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new AuthError
func NewAuthError(err error, code string, reason string, userID string, temporary bool) *AuthError {
	return &AuthError{
		Err:       err,
		Code:      code,
		UserID:    userID,
		Reason:    reason,
		Temporary: temporary,
	}
}

// IsAuthError checks if an error is an AuthError
func IsAuthError(err error) bool {
	var authErr *AuthError
	return errors.As(err, &authErr)
}

// GetAuthError extracts an AuthError from an error
func GetAuthError(err error) (*AuthError, bool) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr, true
	}
	return nil, false
}

// PluginError represents an error related to plugins
type PluginError struct {
	Err         error
	PluginName  string
	PluginType  string
	Description string
}

// Error implements the error interface
func (e *PluginError) Error() string {
	return fmt.Sprintf("plugin error [%s - %s]: %s: %s", 
		e.PluginType, e.PluginName, e.Err.Error(), e.Description)
}

// Unwrap returns the wrapped error
func (e *PluginError) Unwrap() error {
	return e.Err
}

// NewPluginError creates a new PluginError
func NewPluginError(err error, pluginType, pluginName, description string) *PluginError {
	return &PluginError{
		Err:         err,
		PluginType:  pluginType,
		PluginName:  pluginName,
		Description: description,
	}
}

// IsPluginError checks if an error is a PluginError
func IsPluginError(err error) bool {
	var pluginErr *PluginError
	return errors.As(err, &pluginErr)
}

// GetPluginError extracts a PluginError from an error
func GetPluginError(err error) (*PluginError, bool) {
	var pluginErr *PluginError
	if errors.As(err, &pluginErr) {
		return pluginErr, true
	}
	return nil, false
}

// ValidationError represents an error related to validation
type ValidationError struct {
	Err       error
	Field     string
	Value     interface{}
	Constraint string
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error [%s]: %s (got: %v, constraint: %s)", 
		e.Field, e.Err.Error(), e.Value, e.Constraint)
}

// Unwrap returns the wrapped error
func (e *ValidationError) Unwrap() error {
	return e.Err
}

// NewValidationError creates a new ValidationError
func NewValidationError(err error, field string, value interface{}, constraint string) *ValidationError {
	return &ValidationError{
		Err:       err,
		Field:     field,
		Value:     value,
		Constraint: constraint,
	}
}

// IsValidationError checks if an error is a ValidationError
func IsValidationError(err error) bool {
	var validationErr *ValidationError
	return errors.As(err, &validationErr)
}

// GetValidationError extracts a ValidationError from an error
func GetValidationError(err error) (*ValidationError, bool) {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr, true
	}
	return nil, false
}

// StorageError represents an error related to storage operations
type StorageError struct {
	Err         error
	Operation   string
	Entity      string
	StorageType string
}

// Error implements the error interface
func (e *StorageError) Error() string {
	return fmt.Sprintf("storage error [%s - %s - %s]: %s", 
		e.StorageType, e.Entity, e.Operation, e.Err.Error())
}

// Unwrap returns the wrapped error
func (e *StorageError) Unwrap() error {
	return e.Err
}

// NewStorageError creates a new StorageError
func NewStorageError(err error, storageType, entity, operation string) *StorageError {
	return &StorageError{
		Err:         err,
		StorageType: storageType,
		Entity:      entity,
		Operation:   operation,
	}
}

// IsStorageError checks if an error is a StorageError
func IsStorageError(err error) bool {
	var storageErr *StorageError
	return errors.As(err, &storageErr)
}

// GetStorageError extracts a StorageError from an error
func GetStorageError(err error) (*StorageError, bool) {
	var storageErr *StorageError
	if errors.As(err, &storageErr) {
		return storageErr, true
	}
	return nil, false
}

// Is checks if an error matches a target error
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

// New creates a new error with the given message
func New(text string) error {
	return errors.New(text)
}

// Wrap wraps an error with additional context
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}