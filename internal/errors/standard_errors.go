package errors

import (
	"errors"
	"fmt"
)

// Additional standard errors in the auth2 package
var (
	// General errors
	ErrTimeout          = errors.New("operation timed out")
	ErrCanceled         = errors.New("operation canceled")
	ErrAlreadyExists    = errors.New("already exists")
	ErrNotFound         = errors.New("not found")
	ErrServiceUnavailable = errors.New("service unavailable")
	
	// Application-specific errors
	ErrConfiguration    = errors.New("configuration error")
	ErrInitialization   = errors.New("initialization error")
	ErrValidation       = errors.New("validation error")
	ErrUnsupported      = errors.New("unsupported operation")
	ErrUnauthenticated  = errors.New("unauthenticated")
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrRateLimited      = errors.New("rate limited")
	ErrRetryable        = errors.New("retryable error")
	ErrNonRetryable     = errors.New("non-retryable error")
	ErrDependency       = errors.New("dependency error")
)

// ErrorCode defines a code for categorizing errors
type ErrorCode string

const (
	// Error code categories
	CodeInternal         ErrorCode = "internal"
	CodeNotImplemented   ErrorCode = "not_implemented"
	CodeInvalidArgument  ErrorCode = "invalid_argument"
	CodeInvalidOperation ErrorCode = "invalid_operation"
	CodeTimeout          ErrorCode = "timeout"
	CodeCanceled         ErrorCode = "canceled"
	CodeAlreadyExists    ErrorCode = "already_exists"
	CodeNotFound         ErrorCode = "not_found"
	CodeUnavailable      ErrorCode = "unavailable"
	
	CodeConfiguration    ErrorCode = "configuration"
	CodeInitialization   ErrorCode = "initialization"
	CodeValidation       ErrorCode = "validation"
	CodeUnsupported      ErrorCode = "unsupported"
	CodeUnauthenticated  ErrorCode = "unauthenticated"
	CodeUnauthorized     ErrorCode = "unauthorized"
	CodeForbidden        ErrorCode = "forbidden"
	CodeRateLimited      ErrorCode = "rate_limited"
	CodeRetryable        ErrorCode = "retryable"
	CodeNonRetryable     ErrorCode = "non_retryable"
	CodeDependency       ErrorCode = "dependency"
	
	// Authentication-specific codes
	CodeAuthFailed          ErrorCode = "auth_failed"
	CodeInvalidCredentials  ErrorCode = "invalid_credentials"
	CodeUserNotFound        ErrorCode = "user_not_found"
	CodeUserExists          ErrorCode = "user_exists"
	CodeUserDisabled        ErrorCode = "user_disabled"
	CodeUserLocked          ErrorCode = "user_locked"
	CodeMFARequired         ErrorCode = "mfa_required"
	CodeMFAFailed           ErrorCode = "mfa_failed"
	CodeMFANotEnabled       ErrorCode = "mfa_not_enabled"
	CodeMFAAlreadyEnabled   ErrorCode = "mfa_already_enabled"
	CodeSessionExpired      ErrorCode = "session_expired"
	CodeSessionNotFound     ErrorCode = "session_not_found"
	CodeInvalidToken        ErrorCode = "invalid_token"
	CodeTokenExpired        ErrorCode = "token_expired"
	CodePermissionDenied    ErrorCode = "permission_denied"
	CodeRoleNotFound        ErrorCode = "role_not_found"
	CodePasswordWeak        ErrorCode = "password_weak"
	CodePasswordExpired     ErrorCode = "password_expired"
	CodeEmailNotVerified    ErrorCode = "email_not_verified"
	CodeAccountLocked       ErrorCode = "account_locked"
	
	// Storage-specific codes
	CodeStorageError      ErrorCode = "storage_error"
	CodeStorageConnection ErrorCode = "storage_connection"
	CodeStorageQuery      ErrorCode = "storage_query"
	CodeStorageConstraint ErrorCode = "storage_constraint"
	CodeStorageTransaction ErrorCode = "storage_transaction"
	
	// HTTP-specific codes
	CodeHTTPError        ErrorCode = "http_error"
	CodeHTTPClient       ErrorCode = "http_client"
	CodeHTTPServer       ErrorCode = "http_server"
	CodeHTTPBadRequest   ErrorCode = "http_bad_request"
	CodeHTTPUnauthorized ErrorCode = "http_unauthorized"
	CodeHTTPForbidden    ErrorCode = "http_forbidden"
	CodeHTTPNotFound     ErrorCode = "http_not_found"
	CodeHTTPTimeout      ErrorCode = "http_timeout"
	CodeHTTPServerError  ErrorCode = "http_server_error"
)

// standardErrorCodes maps standard errors to error codes
var standardErrorCodes = map[error]ErrorCode{
	ErrInternal:         CodeInternal,
	ErrNotImplemented:   CodeNotImplemented,
	ErrInvalidArgument:  CodeInvalidArgument,
	ErrInvalidOperation: CodeInvalidOperation,
	ErrTimeout:          CodeTimeout,
	ErrCanceled:         CodeCanceled,
	ErrAlreadyExists:    CodeAlreadyExists,
	ErrNotFound:         CodeNotFound,
	ErrServiceUnavailable: CodeUnavailable,
	
	ErrConfiguration:    CodeConfiguration,
	ErrInitialization:   CodeInitialization,
	ErrValidation:       CodeValidation,
	ErrUnsupported:      CodeUnsupported,
	ErrUnauthenticated:  CodeUnauthenticated,
	ErrUnauthorized:     CodeUnauthorized,
	ErrForbidden:        CodeForbidden,
	ErrRateLimited:      CodeRateLimited,
	ErrRetryable:        CodeRetryable,
	ErrNonRetryable:     CodeNonRetryable,
	ErrDependency:       CodeDependency,
}

// GetErrorCode returns the error code for a standard error or "unknown"
func GetErrorCode(err error) ErrorCode {
	if err == nil {
		return ""
	}
	
	// Check for standard errors
	for stdErr, code := range standardErrorCodes {
		if errors.Is(err, stdErr) {
			return code
		}
	}
	
	// Check if the error implements the Coder interface
	var coder Coder
	if errors.As(err, &coder) {
		return coder.Code()
	}
	
	return "unknown"
}

// Coder is an interface for errors that provide an error code
type Coder interface {
	Code() ErrorCode
}

// Error is the base error type for auth2
type Error struct {
	// Err is the underlying error
	Err error
	
	// ErrorCode is the error code
	ErrorCode ErrorCode
	
	// Message is a human-readable error message
	Message string
	
	// Details contains additional error details
	Details map[string]interface{}
	
	// Retryable indicates if the error is retryable
	Retryable bool
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Message != "" {
		return e.Message
	}
	
	if e.Err != nil {
		return e.Err.Error()
	}
	
	return string(e.ErrorCode)
}

// Unwrap returns the wrapped error
func (e *Error) Unwrap() error {
	return e.Err
}

// Code returns the error code
func (e *Error) Code() ErrorCode {
	return e.ErrorCode
}

// Is reports whether err is an Error with the same code
func (e *Error) Is(err error) bool {
	var target *Error
	if errors.As(err, &target) {
		return e.ErrorCode == target.ErrorCode
	}
	return false
}

// WithMessage returns a new error with the given message
func (e *Error) WithMessage(message string) *Error {
	return &Error{
		Err:       e.Err,
		ErrorCode: e.ErrorCode,
		Message:   message,
		Details:   e.Details,
		Retryable: e.Retryable,
	}
}

// WithDetails returns a new error with the given details
func (e *Error) WithDetails(details map[string]interface{}) *Error {
	newError := &Error{
		Err:       e.Err,
		ErrorCode: e.ErrorCode,
		Message:   e.Message,
		Retryable: e.Retryable,
	}
	
	// Create a new map for details
	newError.Details = make(map[string]interface{})
	
	// Copy existing details, if any
	if e.Details != nil {
		for k, v := range e.Details {
			newError.Details[k] = v
		}
	}
	
	// Add the new details
	for k, v := range details {
		newError.Details[k] = v
	}
	
	return newError
}

// WithRetryable returns a new error with the retryable flag set
func (e *Error) WithRetryable(retryable bool) *Error {
	return &Error{
		Err:       e.Err,
		ErrorCode: e.ErrorCode,
		Message:   e.Message,
		Details:   e.Details,
		Retryable: retryable,
	}
}

// ErrorFormatter is a function that formats an error
type ErrorFormatter func(err error) string

// DefaultErrorFormatter is the default error formatter
var DefaultErrorFormatter = func(err error) string {
	var e *Error
	if errors.As(err, &e) {
		if e.Message != "" {
			return fmt.Sprintf("%s (%s)", e.Message, e.ErrorCode)
		}
		return fmt.Sprintf("%s", e.ErrorCode)
	}
	return err.Error()
}

// ErrorLogger is a function that logs an error
type ErrorLogger func(err error, details map[string]interface{})

// DefaultErrorLogger is the default error logger
var DefaultErrorLogger = func(err error, details map[string]interface{}) {
	// This is a placeholder. In a real implementation, this would use a logger
	fmt.Printf("ERROR: %s\n", DefaultErrorFormatter(err))
	if len(details) > 0 {
		fmt.Printf("DETAILS: %v\n", details)
	}
}

// Error creation functions

// NewError creates a new Error
func NewError(code ErrorCode, message string) *Error {
	return &Error{
		ErrorCode: code,
		Message:   message,
		Details:   make(map[string]interface{}),
		Retryable: false,
	}
}

// NewErrorf creates a new Error with a formatted message
func NewErrorf(code ErrorCode, format string, args ...interface{}) *Error {
	return &Error{
		ErrorCode: code,
		Message:   fmt.Sprintf(format, args...),
		Details:   make(map[string]interface{}),
		Retryable: false,
	}
}

// WrapError wraps an error with a code and message
func WrapError(err error, code ErrorCode, message string) *Error {
	return &Error{
		Err:       err,
		ErrorCode: code,
		Message:   message,
		Details:   make(map[string]interface{}),
		Retryable: false,
	}
}

// WrapErrorf wraps an error with a code and formatted message
func WrapErrorf(err error, code ErrorCode, format string, args ...interface{}) *Error {
	return &Error{
		Err:       err,
		ErrorCode: code,
		Message:   fmt.Sprintf(format, args...),
		Details:   make(map[string]interface{}),
		Retryable: false,
	}
}

// Convenience functions for common errors

// NotFound creates a new "not found" error
func NotFound(resource string, id string) *Error {
	return &Error{
		Err:       ErrNotFound,
		ErrorCode: CodeNotFound,
		Message:   fmt.Sprintf("%s not found: %s", resource, id),
		Details: map[string]interface{}{
			"resource": resource,
			"id":       id,
		},
		Retryable: false,
	}
}

// AlreadyExists creates a new "already exists" error
func AlreadyExists(resource string, id string) *Error {
	return &Error{
		Err:       ErrAlreadyExists,
		ErrorCode: CodeAlreadyExists,
		Message:   fmt.Sprintf("%s already exists: %s", resource, id),
		Details: map[string]interface{}{
			"resource": resource,
			"id":       id,
		},
		Retryable: false,
	}
}

// InvalidArgument creates a new "invalid argument" error
func InvalidArgument(argument string, reason string) *Error {
	return &Error{
		Err:       ErrInvalidArgument,
		ErrorCode: CodeInvalidArgument,
		Message:   fmt.Sprintf("invalid argument %s: %s", argument, reason),
		Details: map[string]interface{}{
			"argument": argument,
			"reason":   reason,
		},
		Retryable: false,
	}
}

// Internal creates a new "internal error"
func Internal(message string) *Error {
	return &Error{
		Err:       ErrInternal,
		ErrorCode: CodeInternal,
		Message:   message,
		Details:   make(map[string]interface{}),
		Retryable: false,
	}
}

// Unauthenticated creates a new "unauthenticated" error
func Unauthenticated(reason string) *Error {
	return &Error{
		Err:       ErrUnauthenticated,
		ErrorCode: CodeUnauthenticated,
		Message:   fmt.Sprintf("unauthenticated: %s", reason),
		Details: map[string]interface{}{
			"reason": reason,
		},
		Retryable: false,
	}
}

// Unauthorized creates a new "unauthorized" error
func Unauthorized(reason string) *Error {
	return &Error{
		Err:       ErrUnauthorized,
		ErrorCode: CodeUnauthorized,
		Message:   fmt.Sprintf("unauthorized: %s", reason),
		Details: map[string]interface{}{
			"reason": reason,
		},
		Retryable: false,
	}
}

// PermissionDenied creates a new "permission denied" error
func PermissionDenied(permission string, resource string) *Error {
	return &Error{
		Err:       ErrForbidden,
		ErrorCode: CodePermissionDenied,
		Message:   fmt.Sprintf("permission denied: %s on %s", permission, resource),
		Details: map[string]interface{}{
			"permission": permission,
			"resource":   resource,
		},
		Retryable: false,
	}
}

// Timeout creates a new "timeout" error
func Timeout(operation string, duration string) *Error {
	return &Error{
		Err:       ErrTimeout,
		ErrorCode: CodeTimeout,
		Message:   fmt.Sprintf("operation timed out after %s: %s", duration, operation),
		Details: map[string]interface{}{
			"operation": operation,
			"duration":  duration,
		},
		Retryable: true,
	}
}

// RateLimited creates a new "rate limited" error
func RateLimited(resource string, limit string, retryAfter string) *Error {
	return &Error{
		Err:       ErrRateLimited,
		ErrorCode: CodeRateLimited,
		Message:   fmt.Sprintf("rate limit exceeded for %s: %s", resource, limit),
		Details: map[string]interface{}{
			"resource":    resource,
			"limit":       limit,
			"retry_after": retryAfter,
		},
		Retryable: true,
	}
}

// Validation creates a new "validation error"
func Validation(field string, reason string) *Error {
	return &Error{
		Err:       ErrValidation,
		ErrorCode: CodeValidation,
		Message:   fmt.Sprintf("validation error for %s: %s", field, reason),
		Details: map[string]interface{}{
			"field":  field,
			"reason": reason,
		},
		Retryable: false,
	}
}

// Dependency creates a new "dependency error"
func Dependency(dependency string, err error) *Error {
	return &Error{
		Err:       ErrDependency,
		ErrorCode: CodeDependency,
		Message:   fmt.Sprintf("dependency error: %s: %s", dependency, err.Error()),
		Details: map[string]interface{}{
			"dependency": dependency,
			"error":      err.Error(),
		},
		Retryable: true,
	}
}

// CreateHTTPError creates a new "HTTP error"
func CreateHTTPError(statusCode int, url string, err error) *Error {
	var code ErrorCode
	switch {
	case statusCode >= 500:
		code = CodeHTTPServerError
	case statusCode == 404:
		code = CodeHTTPNotFound
	case statusCode == 403:
		code = CodeHTTPForbidden
	case statusCode == 401:
		code = CodeHTTPUnauthorized
	case statusCode >= 400 && statusCode < 500:
		code = CodeHTTPBadRequest
	default:
		code = CodeHTTPError
	}
	
	var message string
	if err != nil {
		message = fmt.Sprintf("HTTP error %d: %s: %s", statusCode, url, err.Error())
	} else {
		message = fmt.Sprintf("HTTP error %d: %s", statusCode, url)
	}
	
	return &Error{
		Err:       ErrServiceUnavailable,
		ErrorCode: code,
		Message:   message,
		Details: map[string]interface{}{
			"status_code": statusCode,
			"url":         url,
		},
		Retryable: statusCode >= 500 || statusCode == 429,
	}
}

// CreateStorageError creates a new "storage error"
func CreateStorageError(operation, entity string, err error) *Error {
	return &Error{
		Err:       err,
		ErrorCode: CodeStorageError,
		Message:   fmt.Sprintf("storage error: %s on %s: %s", operation, entity, err.Error()),
		Details: map[string]interface{}{
			"operation": operation,
			"entity":    entity,
		},
		Retryable: true,
	}
}

// CreateAuthError creates a new authentication error
func CreateAuthError(code ErrorCode, message string) *Error {
	return &Error{
		Err:       ErrUnauthenticated,
		ErrorCode: code,
		Message:   message,
		Details:   make(map[string]interface{}),
		Retryable: false,
	}
}