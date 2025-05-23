package errors_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	interrors "github.com/Fishwaldo/auth2/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPError(t *testing.T) {
	httpErr := interrors.NewHTTPError(interrors.CodeAuthFailed, "Authentication failed", http.StatusUnauthorized)
	
	assert.Equal(t, string(interrors.CodeAuthFailed), httpErr.Code)
	assert.Equal(t, "Authentication failed", httpErr.Message)
	assert.Equal(t, http.StatusUnauthorized, httpErr.Status)
	assert.NotNil(t, httpErr.Details)
	assert.Empty(t, httpErr.Details)
}

func TestHTTPErrorWithDetails(t *testing.T) {
	original := interrors.NewHTTPError(interrors.CodeAuthFailed, "Authentication failed", http.StatusUnauthorized)
	details := map[string]interface{}{
		"user":   "john",
		"reason": "invalid password",
	}
	
	modified := original.WithDetails(details)
	
	// Check that a new error is returned
	assert.NotSame(t, original, modified)
	
	// Check that details were added
	assert.Equal(t, "john", modified.Details["user"])
	assert.Equal(t, "invalid password", modified.Details["reason"])
	
	// Check that other fields remain the same
	assert.Equal(t, original.Code, modified.Code)
	assert.Equal(t, original.Message, modified.Message)
	assert.Equal(t, original.Status, modified.Status)
	
	// Check that original is unchanged
	assert.Empty(t, original.Details)
}

func TestHTTPErrorWithDetailsMultipleCalls(t *testing.T) {
	original := interrors.NewHTTPError(interrors.CodeAuthFailed, "Authentication failed", http.StatusUnauthorized)
	
	// First add some details
	step1 := original.WithDetails(map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	})
	
	// Then add more details
	step2 := step1.WithDetails(map[string]interface{}{
		"key2": "updated", // This should override
		"key3": "value3",
	})
	
	// Check final state
	assert.Equal(t, "value1", step2.Details["key1"])
	assert.Equal(t, "updated", step2.Details["key2"])
	assert.Equal(t, "value3", step2.Details["key3"])
	
	// Check that previous steps are unchanged
	assert.Empty(t, original.Details)
	assert.Equal(t, "value2", step1.Details["key2"])
	assert.Nil(t, step1.Details["key3"])
}

func TestHTTPErrorWriteResponse(t *testing.T) {
	tests := []struct {
		name           string
		httpErr        *interrors.HTTPError
		expectedStatus int
		expectedBody   interrors.HTTPErrorResponse
	}{
		{
			name: "basic error response",
			httpErr: interrors.NewHTTPError(
				interrors.CodeAuthFailed,
				"Authentication failed",
				http.StatusUnauthorized,
			),
			expectedStatus: http.StatusUnauthorized,
			expectedBody: interrors.HTTPErrorResponse{
				Error: interrors.HTTPError{
					Code:    string(interrors.CodeAuthFailed),
					Message: "Authentication failed",
					Details: map[string]interface{}{},
				},
			},
		},
		{
			name: "error response with details",
			httpErr: interrors.NewHTTPError(
				interrors.CodeValidation,
				"Validation failed",
				http.StatusBadRequest,
			).WithDetails(map[string]interface{}{
				"field":  "email",
				"reason": "invalid format",
			}),
			expectedStatus: http.StatusBadRequest,
			expectedBody: interrors.HTTPErrorResponse{
				Error: interrors.HTTPError{
					Code:    string(interrors.CodeValidation),
					Message: "Validation failed",
					Details: map[string]interface{}{
						"field":  "email",
						"reason": "invalid format",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test response writer
			w := httptest.NewRecorder()
			
			// Write the error response
			tt.httpErr.WriteResponse(w)
			
			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			// Check content type
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			
			// Check response body
			var response interrors.HTTPErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedBody.Error.Code, response.Error.Code)
			assert.Equal(t, tt.expectedBody.Error.Message, response.Error.Message)
			
			// For details, check each key individually since map comparison can be tricky
			if tt.expectedBody.Error.Details != nil {
				for k, v := range tt.expectedBody.Error.Details {
					assert.Equal(t, v, response.Error.Details[k])
				}
			}
		})
	}
}

func TestErrorToHTTP(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedCode   string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "nil error",
			err:            nil,
			expectedCode:   "",
			expectedStatus: 0,
			expectedMsg:    "",
		},
		{
			name:           "standard not found error",
			err:            interrors.ErrNotFound,
			expectedCode:   "internal",
			expectedStatus: http.StatusNotFound,
			expectedMsg:    "not found",
		},
		{
			name:           "standard unauthorized error",
			err:            interrors.ErrUnauthenticated,
			expectedCode:   "internal",
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "unauthenticated",
		},
		{
			name:           "standard forbidden error",
			err:            interrors.ErrForbidden,
			expectedCode:   "internal",
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "forbidden",
		},
		{
			name:           "standard rate limited error",
			err:            interrors.ErrRateLimited,
			expectedCode:   "internal",
			expectedStatus: http.StatusTooManyRequests,
			expectedMsg:    "rate limited",
		},
		{
			name:           "standard timeout error",
			err:            interrors.ErrTimeout,
			expectedCode:   "internal",
			expectedStatus: http.StatusGatewayTimeout,
			expectedMsg:    "operation timed out",
		},
		{
			name:           "standard canceled error",
			err:            interrors.ErrCanceled,
			expectedCode:   "internal",
			expectedStatus: http.StatusRequestTimeout,
			expectedMsg:    "operation canceled",
		},
		{
			name:           "standard service unavailable error",
			err:            interrors.ErrServiceUnavailable,
			expectedCode:   "internal",
			expectedStatus: http.StatusServiceUnavailable,
			expectedMsg:    "service unavailable",
		},
		{
			name: "Error type with code",
			err: &interrors.Error{
				ErrorCode: interrors.CodeValidation,
				Message:   "Invalid email format",
				Details: map[string]interface{}{
					"field": "email",
				},
			},
			expectedCode:   string(interrors.CodeValidation),
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid email format",
		},
		{
			name:           "unknown error",
			err:            errors.New("unknown error"),
			expectedCode:   "internal",
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "unknown error",
		},
		{
			name:           "wrapped standard error",
			err:            errors.Join(errors.New("context"), interrors.ErrNotFound),
			expectedCode:   "internal",
			expectedStatus: http.StatusNotFound,
			expectedMsg:    "context\nnot found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpErr := interrors.ErrorToHTTP(tt.err)
			
			if tt.err == nil {
				assert.Nil(t, httpErr)
			} else {
				require.NotNil(t, httpErr)
				assert.Equal(t, tt.expectedCode, httpErr.Code)
				assert.Equal(t, tt.expectedStatus, httpErr.Status)
				assert.Equal(t, tt.expectedMsg, httpErr.Message)
			}
		})
	}
}

func TestCommonHTTPErrors(t *testing.T) {
	tests := []struct {
		name           string
		httpErr        *interrors.HTTPError
		expectedCode   interrors.ErrorCode
		expectedStatus int
	}{
		{
			name:           "HTTPErrBadRequest",
			httpErr:        interrors.HTTPErrBadRequest,
			expectedCode:   interrors.CodeInvalidArgument,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "HTTPErrUnauthorized",
			httpErr:        interrors.HTTPErrUnauthorized,
			expectedCode:   interrors.CodeUnauthenticated,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "HTTPErrForbidden",
			httpErr:        interrors.HTTPErrForbidden,
			expectedCode:   interrors.CodeForbidden,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "HTTPErrNotFound",
			httpErr:        interrors.HTTPErrNotFound,
			expectedCode:   interrors.CodeNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "HTTPErrMethodNotAllowed",
			httpErr:        interrors.HTTPErrMethodNotAllowed,
			expectedCode:   interrors.CodeUnsupported,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "HTTPErrConflict",
			httpErr:        interrors.HTTPErrConflict,
			expectedCode:   interrors.CodeAlreadyExists,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "HTTPErrTooManyRequests",
			httpErr:        interrors.HTTPErrTooManyRequests,
			expectedCode:   interrors.CodeRateLimited,
			expectedStatus: http.StatusTooManyRequests,
		},
		{
			name:           "HTTPErrInternalServerError",
			httpErr:        interrors.HTTPErrInternalServerError,
			expectedCode:   interrors.CodeInternal,
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "HTTPErrServiceUnavailable",
			httpErr:        interrors.HTTPErrServiceUnavailable,
			expectedCode:   interrors.CodeUnavailable,
			expectedStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, string(tt.expectedCode), tt.httpErr.Code)
			assert.Equal(t, tt.expectedStatus, tt.httpErr.Status)
			assert.NotEmpty(t, tt.httpErr.Message)
			assert.NotNil(t, tt.httpErr.Details)
		})
	}
}

func TestWriteErrorResponse(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "standard error",
			err:            interrors.ErrNotFound,
			expectedStatus: http.StatusNotFound,
			expectedCode:   "internal",
		},
		{
			name: "Error type",
			err: &interrors.Error{
				ErrorCode: interrors.CodeValidation,
				Message:   "Invalid input",
			},
			expectedStatus: http.StatusBadRequest,
			expectedCode:   string(interrors.CodeValidation),
		},
		{
			name:           "unknown error",
			err:            errors.New("something went wrong"),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "internal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test response writer
			w := httptest.NewRecorder()
			
			// Write the error response
			interrors.WriteErrorResponse(w, tt.err)
			
			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			// Check content type
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			
			// Check response body
			var response interrors.HTTPErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedCode, response.Error.Code)
			assert.NotEmpty(t, response.Error.Message)
		})
	}
}

func TestWriteJSONError(t *testing.T) {
	// Create a test response writer
	w := httptest.NewRecorder()
	
	// Write the JSON error
	interrors.WriteJSONError(
		w,
		interrors.CodeValidation,
		"Email format is invalid",
		http.StatusBadRequest,
	)
	
	// Check status code
	assert.Equal(t, http.StatusBadRequest, w.Code)
	
	// Check content type
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	
	// Check response body
	var response interrors.HTTPErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	
	assert.Equal(t, string(interrors.CodeValidation), response.Error.Code)
	assert.Equal(t, "Email format is invalid", response.Error.Message)
	// Details can be nil or empty map after JSON unmarshaling
	// Both are acceptable for an error with no details
}

func TestErrorToHTTPStatus(t *testing.T) {
	// This function is not exported, but we can test it indirectly through ErrorToHTTP
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		// Test standard errors
		{
			name:           "ErrNotFound",
			err:            interrors.ErrNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "ErrAlreadyExists",
			err:            interrors.ErrAlreadyExists,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "ErrInvalidArgument",
			err:            interrors.ErrInvalidArgument,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrInvalidOperation",
			err:            interrors.ErrInvalidOperation,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "ErrUnauthenticated",
			err:            interrors.ErrUnauthenticated,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "ErrUnauthorized",
			err:            interrors.ErrUnauthorized,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "ErrForbidden",
			err:            interrors.ErrForbidden,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "ErrRateLimited",
			err:            interrors.ErrRateLimited,
			expectedStatus: http.StatusTooManyRequests,
		},
		{
			name:           "ErrTimeout",
			err:            interrors.ErrTimeout,
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name:           "ErrCanceled",
			err:            interrors.ErrCanceled,
			expectedStatus: http.StatusRequestTimeout,
		},
		{
			name:           "ErrServiceUnavailable",
			err:            interrors.ErrServiceUnavailable,
			expectedStatus: http.StatusServiceUnavailable,
		},
		// Test errors with codes
		{
			name:           "Error with CodeNotFound",
			err:            &interrors.Error{ErrorCode: interrors.CodeNotFound},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Error with CodeAlreadyExists",
			err:            &interrors.Error{ErrorCode: interrors.CodeAlreadyExists},
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "Error with CodeInvalidArgument",
			err:            &interrors.Error{ErrorCode: interrors.CodeInvalidArgument},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Error with CodeInvalidOperation",
			err:            &interrors.Error{ErrorCode: interrors.CodeInvalidOperation},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Error with CodeUnauthenticated",
			err:            &interrors.Error{ErrorCode: interrors.CodeUnauthenticated},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Error with CodeUnauthorized",
			err:            &interrors.Error{ErrorCode: interrors.CodeUnauthorized},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Error with CodeForbidden",
			err:            &interrors.Error{ErrorCode: interrors.CodeForbidden},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Error with CodeRateLimited",
			err:            &interrors.Error{ErrorCode: interrors.CodeRateLimited},
			expectedStatus: http.StatusTooManyRequests,
		},
		{
			name:           "Error with CodeTimeout",
			err:            &interrors.Error{ErrorCode: interrors.CodeTimeout},
			expectedStatus: http.StatusGatewayTimeout,
		},
		{
			name:           "Error with CodeCanceled",
			err:            &interrors.Error{ErrorCode: interrors.CodeCanceled},
			expectedStatus: http.StatusRequestTimeout,
		},
		{
			name:           "Error with CodeUnavailable",
			err:            &interrors.Error{ErrorCode: interrors.CodeUnavailable},
			expectedStatus: http.StatusServiceUnavailable,
		},
		// Default case
		{
			name:           "unknown error",
			err:            errors.New("unknown"),
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Error with unknown code",
			err:            &interrors.Error{ErrorCode: "unknown_code"},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpErr := interrors.ErrorToHTTP(tt.err)
			require.NotNil(t, httpErr)
			assert.Equal(t, tt.expectedStatus, httpErr.Status)
		})
	}
}