package errors_test

import (
	"errors"
	"fmt"
	"testing"

	interrors "github.com/Fishwaldo/auth2/internal/errors"
	"github.com/stretchr/testify/assert"
)

func TestStandardErrorsDefinitions(t *testing.T) {
	// Test that all additional standard errors are defined
	standardErrors := []struct {
		name string
		err  error
	}{
		// General errors
		{"ErrTimeout", interrors.ErrTimeout},
		{"ErrCanceled", interrors.ErrCanceled},
		{"ErrAlreadyExists", interrors.ErrAlreadyExists},
		{"ErrNotFound", interrors.ErrNotFound},
		{"ErrServiceUnavailable", interrors.ErrServiceUnavailable},
		
		// Application-specific errors
		{"ErrConfiguration", interrors.ErrConfiguration},
		{"ErrInitialization", interrors.ErrInitialization},
		{"ErrValidation", interrors.ErrValidation},
		{"ErrUnsupported", interrors.ErrUnsupported},
		{"ErrUnauthenticated", interrors.ErrUnauthenticated},
		{"ErrUnauthorized", interrors.ErrUnauthorized},
		{"ErrForbidden", interrors.ErrForbidden},
		{"ErrRateLimited", interrors.ErrRateLimited},
		{"ErrRetryable", interrors.ErrRetryable},
		{"ErrNonRetryable", interrors.ErrNonRetryable},
		{"ErrDependency", interrors.ErrDependency},
	}

	for _, tt := range standardErrors {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err)
			assert.Error(t, tt.err)
		})
	}
}

func TestErrorCodes(t *testing.T) {
	// Test that all error codes are defined
	codes := []interrors.ErrorCode{
		// General codes
		interrors.CodeInternal,
		interrors.CodeNotImplemented,
		interrors.CodeInvalidArgument,
		interrors.CodeInvalidOperation,
		interrors.CodeTimeout,
		interrors.CodeCanceled,
		interrors.CodeAlreadyExists,
		interrors.CodeNotFound,
		interrors.CodeUnavailable,
		
		// Application codes
		interrors.CodeConfiguration,
		interrors.CodeInitialization,
		interrors.CodeValidation,
		interrors.CodeUnsupported,
		interrors.CodeUnauthenticated,
		interrors.CodeUnauthorized,
		interrors.CodeForbidden,
		interrors.CodeRateLimited,
		interrors.CodeRetryable,
		interrors.CodeNonRetryable,
		interrors.CodeDependency,
		
		// Authentication codes
		interrors.CodeAuthFailed,
		interrors.CodeInvalidCredentials,
		interrors.CodeUserNotFound,
		interrors.CodeUserExists,
		interrors.CodeUserDisabled,
		interrors.CodeUserLocked,
		interrors.CodeMFARequired,
		interrors.CodeMFAFailed,
		interrors.CodeMFANotEnabled,
		interrors.CodeMFAAlreadyEnabled,
		interrors.CodeSessionExpired,
		interrors.CodeSessionNotFound,
		interrors.CodeInvalidToken,
		interrors.CodeTokenExpired,
		interrors.CodePermissionDenied,
		interrors.CodeRoleNotFound,
		interrors.CodePasswordWeak,
		interrors.CodePasswordExpired,
		interrors.CodeEmailNotVerified,
		interrors.CodeAccountLocked,
		
		// Storage codes
		interrors.CodeStorageError,
		interrors.CodeStorageConnection,
		interrors.CodeStorageQuery,
		interrors.CodeStorageConstraint,
		interrors.CodeStorageTransaction,
		
		// HTTP codes
		interrors.CodeHTTPError,
		interrors.CodeHTTPClient,
		interrors.CodeHTTPServer,
		interrors.CodeHTTPBadRequest,
		interrors.CodeHTTPUnauthorized,
		interrors.CodeHTTPForbidden,
		interrors.CodeHTTPNotFound,
		interrors.CodeHTTPTimeout,
		interrors.CodeHTTPServerError,
	}

	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			assert.NotEmpty(t, code)
		})
	}
}

func TestGetErrorCode(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode interrors.ErrorCode
	}{
		{
			name:         "nil error",
			err:          nil,
			expectedCode: "",
		},
		{
			name:         "standard error - internal",
			err:          interrors.ErrInternal,
			expectedCode: interrors.CodeInternal,
		},
		{
			name:         "standard error - not found",
			err:          interrors.ErrNotFound,
			expectedCode: interrors.CodeNotFound,
		},
		{
			name:         "wrapped standard error",
			err:          fmt.Errorf("wrapped: %w", interrors.ErrTimeout),
			expectedCode: interrors.CodeTimeout,
		},
		{
			name:         "error with code",
			err:          interrors.NewError(interrors.CodeAuthFailed, "authentication failed"),
			expectedCode: interrors.CodeAuthFailed,
		},
		{
			name:         "unknown error",
			err:          errors.New("unknown error"),
			expectedCode: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := interrors.GetErrorCode(tt.err)
			assert.Equal(t, tt.expectedCode, code)
		})
	}
}

func TestError(t *testing.T) {
	tests := []struct {
		name          string
		err           *interrors.Error
		expectedError string
		expectedCode  interrors.ErrorCode
		isRetryable   bool
	}{
		{
			name: "error with message",
			err: &interrors.Error{
				ErrorCode: interrors.CodeAuthFailed,
				Message:   "authentication failed for user",
			},
			expectedError: "authentication failed for user",
			expectedCode:  interrors.CodeAuthFailed,
			isRetryable:   false,
		},
		{
			name: "error with wrapped error",
			err: &interrors.Error{
				Err:       errors.New("underlying error"),
				ErrorCode: interrors.CodeInternal,
			},
			expectedError: "underlying error",
			expectedCode:  interrors.CodeInternal,
			isRetryable:   false,
		},
		{
			name: "error with code only",
			err: &interrors.Error{
				ErrorCode: interrors.CodeNotFound,
			},
			expectedError: "not_found",
			expectedCode:  interrors.CodeNotFound,
			isRetryable:   false,
		},
		{
			name: "retryable error",
			err: &interrors.Error{
				ErrorCode: interrors.CodeTimeout,
				Message:   "request timeout",
				Retryable: true,
			},
			expectedError: "request timeout",
			expectedCode:  interrors.CodeTimeout,
			isRetryable:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedError, tt.err.Error())
			assert.Equal(t, tt.expectedCode, tt.err.Code())
			assert.Equal(t, tt.isRetryable, tt.err.Retryable)
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	baseErr := errors.New("base error")
	err := &interrors.Error{
		Err:       baseErr,
		ErrorCode: interrors.CodeInternal,
		Message:   "wrapped error",
	}

	unwrapped := err.Unwrap()
	assert.Equal(t, baseErr, unwrapped)
	assert.True(t, errors.Is(err, baseErr))
}

func TestErrorIsMethod(t *testing.T) {
	err1 := &interrors.Error{ErrorCode: interrors.CodeAuthFailed}
	err2 := &interrors.Error{ErrorCode: interrors.CodeAuthFailed}
	err3 := &interrors.Error{ErrorCode: interrors.CodeNotFound}
	plainErr := errors.New("plain error")

	assert.True(t, err1.Is(err2))
	assert.False(t, err1.Is(err3))
	assert.False(t, err1.Is(plainErr))
}

func TestErrorWithMessage(t *testing.T) {
	original := &interrors.Error{
		ErrorCode: interrors.CodeAuthFailed,
		Message:   "original message",
		Details:   map[string]interface{}{"key": "value"},
		Retryable: true,
	}

	modified := original.WithMessage("new message")

	// Check that a new error is returned
	assert.NotSame(t, original, modified)
	
	// Check that only the message changed
	assert.Equal(t, "new message", modified.Message)
	assert.Equal(t, original.ErrorCode, modified.ErrorCode)
	assert.Equal(t, original.Details, modified.Details)
	assert.Equal(t, original.Retryable, modified.Retryable)
	
	// Check that original is unchanged
	assert.Equal(t, "original message", original.Message)
}

func TestErrorWithDetails(t *testing.T) {
	original := &interrors.Error{
		ErrorCode: interrors.CodeAuthFailed,
		Message:   "error message",
		Details:   map[string]interface{}{"key1": "value1"},
		Retryable: true,
	}

	modified := original.WithDetails(map[string]interface{}{
		"key2": "value2",
		"key1": "updated", // This should override the original key1
	})

	// Check that a new error is returned
	assert.NotSame(t, original, modified)
	
	// Check that details were merged correctly
	assert.Equal(t, "updated", modified.Details["key1"])
	assert.Equal(t, "value2", modified.Details["key2"])
	
	// Check that other fields remain the same
	assert.Equal(t, original.ErrorCode, modified.ErrorCode)
	assert.Equal(t, original.Message, modified.Message)
	assert.Equal(t, original.Retryable, modified.Retryable)
	
	// Check that original is unchanged
	assert.Equal(t, "value1", original.Details["key1"])
	assert.Nil(t, original.Details["key2"])
}

func TestErrorWithDetailsNilOriginal(t *testing.T) {
	original := &interrors.Error{
		ErrorCode: interrors.CodeAuthFailed,
		Message:   "error message",
		Details:   nil,
	}

	modified := original.WithDetails(map[string]interface{}{
		"key": "value",
	})

	assert.Equal(t, "value", modified.Details["key"])
}

func TestErrorWithRetryable(t *testing.T) {
	original := &interrors.Error{
		ErrorCode: interrors.CodeAuthFailed,
		Message:   "error message",
		Retryable: false,
	}

	modified := original.WithRetryable(true)

	// Check that a new error is returned
	assert.NotSame(t, original, modified)
	
	// Check that only retryable changed
	assert.True(t, modified.Retryable)
	assert.Equal(t, original.ErrorCode, modified.ErrorCode)
	assert.Equal(t, original.Message, modified.Message)
	
	// Check that original is unchanged
	assert.False(t, original.Retryable)
}

func TestDefaultErrorFormatter(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "Error with message and code",
			err:      interrors.NewError(interrors.CodeAuthFailed, "authentication failed"),
			expected: "authentication failed (auth_failed)",
		},
		{
			name:     "Error with code only",
			err:      &interrors.Error{ErrorCode: interrors.CodeNotFound},
			expected: "not_found",
		},
		{
			name:     "plain error",
			err:      errors.New("plain error"),
			expected: "plain error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interrors.DefaultErrorFormatter(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewError(t *testing.T) {
	err := interrors.NewError(interrors.CodeAuthFailed, "authentication failed")
	
	assert.Equal(t, interrors.CodeAuthFailed, err.ErrorCode)
	assert.Equal(t, "authentication failed", err.Message)
	assert.NotNil(t, err.Details)
	assert.Empty(t, err.Details)
	assert.False(t, err.Retryable)
}

func TestNewErrorf(t *testing.T) {
	err := interrors.NewErrorf(interrors.CodeAuthFailed, "authentication failed for user %s", "john")
	
	assert.Equal(t, interrors.CodeAuthFailed, err.ErrorCode)
	assert.Equal(t, "authentication failed for user john", err.Message)
	assert.NotNil(t, err.Details)
	assert.Empty(t, err.Details)
	assert.False(t, err.Retryable)
}

func TestWrapError(t *testing.T) {
	baseErr := errors.New("base error")
	wrapped := interrors.WrapError(baseErr, interrors.CodeInternal, "additional context")
	
	assert.Equal(t, baseErr, wrapped.Err)
	assert.Equal(t, interrors.CodeInternal, wrapped.ErrorCode)
	assert.Equal(t, "additional context", wrapped.Message)
	assert.NotNil(t, wrapped.Details)
	assert.False(t, wrapped.Retryable)
	assert.True(t, errors.Is(wrapped, baseErr))
}

func TestWrapErrorf(t *testing.T) {
	baseErr := errors.New("base error")
	wrapped := interrors.WrapErrorf(baseErr, interrors.CodeInternal, "context: %s", "test")
	
	assert.Equal(t, baseErr, wrapped.Err)
	assert.Equal(t, interrors.CodeInternal, wrapped.ErrorCode)
	assert.Equal(t, "context: test", wrapped.Message)
	assert.NotNil(t, wrapped.Details)
	assert.False(t, wrapped.Retryable)
}

func TestConvenienceErrorFunctions(t *testing.T) {
	tests := []struct {
		name        string
		createError func() *interrors.Error
		checkError  func(*testing.T, *interrors.Error)
	}{
		{
			name: "NotFound",
			createError: func() *interrors.Error {
				return interrors.NotFound("user", "123")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrNotFound, err.Err)
				assert.Equal(t, interrors.CodeNotFound, err.ErrorCode)
				assert.Contains(t, err.Message, "user not found: 123")
				assert.Equal(t, "user", err.Details["resource"])
				assert.Equal(t, "123", err.Details["id"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "AlreadyExists",
			createError: func() *interrors.Error {
				return interrors.AlreadyExists("user", "123")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrAlreadyExists, err.Err)
				assert.Equal(t, interrors.CodeAlreadyExists, err.ErrorCode)
				assert.Contains(t, err.Message, "user already exists: 123")
				assert.Equal(t, "user", err.Details["resource"])
				assert.Equal(t, "123", err.Details["id"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "InvalidArgument",
			createError: func() *interrors.Error {
				return interrors.InvalidArgument("email", "invalid format")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrInvalidArgument, err.Err)
				assert.Equal(t, interrors.CodeInvalidArgument, err.ErrorCode)
				assert.Contains(t, err.Message, "invalid argument email: invalid format")
				assert.Equal(t, "email", err.Details["argument"])
				assert.Equal(t, "invalid format", err.Details["reason"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "Internal",
			createError: func() *interrors.Error {
				return interrors.Internal("something went wrong")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrInternal, err.Err)
				assert.Equal(t, interrors.CodeInternal, err.ErrorCode)
				assert.Equal(t, "something went wrong", err.Message)
				assert.Empty(t, err.Details)
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "Unauthenticated",
			createError: func() *interrors.Error {
				return interrors.Unauthenticated("invalid token")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrUnauthenticated, err.Err)
				assert.Equal(t, interrors.CodeUnauthenticated, err.ErrorCode)
				assert.Contains(t, err.Message, "unauthenticated: invalid token")
				assert.Equal(t, "invalid token", err.Details["reason"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "Unauthorized",
			createError: func() *interrors.Error {
				return interrors.Unauthorized("insufficient permissions")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrUnauthorized, err.Err)
				assert.Equal(t, interrors.CodeUnauthorized, err.ErrorCode)
				assert.Contains(t, err.Message, "unauthorized: insufficient permissions")
				assert.Equal(t, "insufficient permissions", err.Details["reason"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "PermissionDenied",
			createError: func() *interrors.Error {
				return interrors.PermissionDenied("write", "documents")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrForbidden, err.Err)
				assert.Equal(t, interrors.CodePermissionDenied, err.ErrorCode)
				assert.Contains(t, err.Message, "permission denied: write on documents")
				assert.Equal(t, "write", err.Details["permission"])
				assert.Equal(t, "documents", err.Details["resource"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "Timeout",
			createError: func() *interrors.Error {
				return interrors.Timeout("database query", "30s")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrTimeout, err.Err)
				assert.Equal(t, interrors.CodeTimeout, err.ErrorCode)
				assert.Contains(t, err.Message, "operation timed out after 30s: database query")
				assert.Equal(t, "database query", err.Details["operation"])
				assert.Equal(t, "30s", err.Details["duration"])
				assert.True(t, err.Retryable)
			},
		},
		{
			name: "RateLimited",
			createError: func() *interrors.Error {
				return interrors.RateLimited("/api/users", "100 req/min", "60s")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrRateLimited, err.Err)
				assert.Equal(t, interrors.CodeRateLimited, err.ErrorCode)
				assert.Contains(t, err.Message, "rate limit exceeded for /api/users: 100 req/min")
				assert.Equal(t, "/api/users", err.Details["resource"])
				assert.Equal(t, "100 req/min", err.Details["limit"])
				assert.Equal(t, "60s", err.Details["retry_after"])
				assert.True(t, err.Retryable)
			},
		},
		{
			name: "Validation",
			createError: func() *interrors.Error {
				return interrors.Validation("age", "must be positive")
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrValidation, err.Err)
				assert.Equal(t, interrors.CodeValidation, err.ErrorCode)
				assert.Contains(t, err.Message, "validation error for age: must be positive")
				assert.Equal(t, "age", err.Details["field"])
				assert.Equal(t, "must be positive", err.Details["reason"])
				assert.False(t, err.Retryable)
			},
		},
		{
			name: "Dependency",
			createError: func() *interrors.Error {
				return interrors.Dependency("redis", errors.New("connection refused"))
			},
			checkError: func(t *testing.T, err *interrors.Error) {
				assert.Equal(t, interrors.ErrDependency, err.Err)
				assert.Equal(t, interrors.CodeDependency, err.ErrorCode)
				assert.Contains(t, err.Message, "dependency error: redis: connection refused")
				assert.Equal(t, "redis", err.Details["dependency"])
				assert.Equal(t, "connection refused", err.Details["error"])
				assert.True(t, err.Retryable)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.createError()
			tt.checkError(t, err)
		})
	}
}

func TestCreateHTTPError(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		url          string
		err          error
		expectedCode interrors.ErrorCode
		isRetryable  bool
	}{
		{
			name:         "server error",
			statusCode:   500,
			url:          "https://api.example.com",
			err:          errors.New("internal server error"),
			expectedCode: interrors.CodeHTTPServerError,
			isRetryable:  true,
		},
		{
			name:         "not found",
			statusCode:   404,
			url:          "https://api.example.com/user/123",
			err:          nil,
			expectedCode: interrors.CodeHTTPNotFound,
			isRetryable:  false,
		},
		{
			name:         "forbidden",
			statusCode:   403,
			url:          "https://api.example.com/admin",
			err:          errors.New("access denied"),
			expectedCode: interrors.CodeHTTPForbidden,
			isRetryable:  false,
		},
		{
			name:         "unauthorized",
			statusCode:   401,
			url:          "https://api.example.com/profile",
			err:          errors.New("invalid token"),
			expectedCode: interrors.CodeHTTPUnauthorized,
			isRetryable:  false,
		},
		{
			name:         "bad request",
			statusCode:   400,
			url:          "https://api.example.com/users",
			err:          errors.New("invalid request body"),
			expectedCode: interrors.CodeHTTPBadRequest,
			isRetryable:  false,
		},
		{
			name:         "rate limited",
			statusCode:   429,
			url:          "https://api.example.com/search",
			err:          errors.New("too many requests"),
			expectedCode: interrors.CodeHTTPBadRequest, // 429 falls into 400-499 range
			isRetryable:  true, // 429 is retryable
		},
		{
			name:         "service unavailable",
			statusCode:   503,
			url:          "https://api.example.com/health",
			err:          nil,
			expectedCode: interrors.CodeHTTPServerError,
			isRetryable:  true,
		},
		{
			name:         "success code (edge case)",
			statusCode:   200,
			url:          "https://api.example.com/success",
			err:          errors.New("unexpected error with 200"),
			expectedCode: interrors.CodeHTTPError,
			isRetryable:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpErr := interrors.CreateHTTPError(tt.statusCode, tt.url, tt.err)
			
			assert.Equal(t, interrors.ErrServiceUnavailable, httpErr.Err)
			assert.Equal(t, tt.expectedCode, httpErr.ErrorCode)
			assert.Contains(t, httpErr.Message, fmt.Sprintf("HTTP error %d", tt.statusCode))
			assert.Contains(t, httpErr.Message, tt.url)
			if tt.err != nil {
				assert.Contains(t, httpErr.Message, tt.err.Error())
			}
			assert.Equal(t, tt.statusCode, httpErr.Details["status_code"])
			assert.Equal(t, tt.url, httpErr.Details["url"])
			assert.Equal(t, tt.isRetryable, httpErr.Retryable)
		})
	}
}

func TestCreateStorageError(t *testing.T) {
	dbErr := errors.New("connection timeout")
	storageErr := interrors.CreateStorageError("insert", "users", dbErr)
	
	assert.Equal(t, dbErr, storageErr.Err)
	assert.Equal(t, interrors.CodeStorageError, storageErr.ErrorCode)
	assert.Contains(t, storageErr.Message, "storage error: insert on users: connection timeout")
	assert.Equal(t, "insert", storageErr.Details["operation"])
	assert.Equal(t, "users", storageErr.Details["entity"])
	assert.True(t, storageErr.Retryable)
	assert.True(t, errors.Is(storageErr, dbErr))
}

func TestCreateAuthError(t *testing.T) {
	authErr := interrors.CreateAuthError(interrors.CodeInvalidCredentials, "incorrect password")
	
	assert.Equal(t, interrors.ErrUnauthenticated, authErr.Err)
	assert.Equal(t, interrors.CodeInvalidCredentials, authErr.ErrorCode)
	assert.Equal(t, "incorrect password", authErr.Message)
	assert.NotNil(t, authErr.Details)
	assert.Empty(t, authErr.Details)
	assert.False(t, authErr.Retryable)
}

func TestDefaultErrorLogger(t *testing.T) {
	// This is just to ensure it doesn't panic
	// In a real test, we would capture stdout or use a proper logger
	err := interrors.NewError(interrors.CodeAuthFailed, "test error")
	details := map[string]interface{}{
		"user": "test",
		"ip":   "127.0.0.1",
	}
	
	// Should not panic
	interrors.DefaultErrorLogger(err, details)
	interrors.DefaultErrorLogger(err, nil)
	interrors.DefaultErrorLogger(errors.New("plain error"), details)
}