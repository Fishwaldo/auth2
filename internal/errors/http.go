package errors

import (
	"encoding/json"
	"net/http"
	stderrors "errors"
)

// HTTPError represents an error returned via HTTP
type HTTPError struct {
	// Code is the error code
	Code string `json:"code"`
	
	// Message is the error message
	Message string `json:"message"`
	
	// Details contains additional error details
	Details map[string]interface{} `json:"details,omitempty"`
	
	// Status is the HTTP status code
	Status int `json:"-"`
}

// HTTPErrorResponse is the response body for HTTP errors
type HTTPErrorResponse struct {
	// Error is the error information
	Error HTTPError `json:"error"`
}

// NewHTTPError creates a new HTTPError
func NewHTTPError(code ErrorCode, message string, status int) *HTTPError {
	return &HTTPError{
		Code:    string(code),
		Message: message,
		Details: make(map[string]interface{}),
		Status:  status,
	}
}

// WithDetails adds details to the HTTPError
func (e *HTTPError) WithDetails(details map[string]interface{}) *HTTPError {
	// Create a new error
	newError := &HTTPError{
		Code:    e.Code,
		Message: e.Message,
		Status:  e.Status,
		Details: make(map[string]interface{}),
	}
	
	// Copy existing details, if any
	for k, v := range e.Details {
		newError.Details[k] = v
	}
	
	// Add new details
	for k, v := range details {
		newError.Details[k] = v
	}
	
	return newError
}

// WriteResponse writes the HTTPError to the HTTP response
func (e *HTTPError) WriteResponse(w http.ResponseWriter) {
	response := HTTPErrorResponse{
		Error: *e,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	
	// If there's an error encoding the response, log it but don't try to write it
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// In a real implementation, this would use a logger
		// log.Printf("Error encoding error response: %v", err)
	}
}

// ErrorToHTTP converts an Error to an HTTPError
func ErrorToHTTP(err error) *HTTPError {
	if err == nil {
		return nil
	}
	
	// Check if we have a direct mapping for this error to a status code
	status := errorToHTTPStatus(err)
	
	// Default to internal server error for unknown errors
	httpErr := &HTTPError{
		Code:    "internal",
		Message: err.Error(),
		Details: make(map[string]interface{}),
		Status:  status, // Use the status from errorToHTTPStatus
	}
	
	// Check if the error is an Error
	var e *Error
	if stderrors.As(err, &e) {
		message := e.Message
		if message == "" {
			message = e.Error()
		}
		httpErr = &HTTPError{
			Code:    string(e.ErrorCode),
			Message: message,
			Details: e.Details,
			Status:  status,
		}
	}
	
	return httpErr
}

// Common HTTP errors
var (
	HTTPErrBadRequest          = NewHTTPError(CodeInvalidArgument, "Bad request", http.StatusBadRequest)
	HTTPErrUnauthorized        = NewHTTPError(CodeUnauthenticated, "Unauthorized", http.StatusUnauthorized)
	HTTPErrForbidden           = NewHTTPError(CodeForbidden, "Forbidden", http.StatusForbidden)
	HTTPErrNotFound            = NewHTTPError(CodeNotFound, "Not found", http.StatusNotFound)
	HTTPErrMethodNotAllowed    = NewHTTPError(CodeUnsupported, "Method not allowed", http.StatusMethodNotAllowed)
	HTTPErrConflict            = NewHTTPError(CodeAlreadyExists, "Conflict", http.StatusConflict)
	HTTPErrTooManyRequests     = NewHTTPError(CodeRateLimited, "Too many requests", http.StatusTooManyRequests)
	HTTPErrInternalServerError = NewHTTPError(CodeInternal, "Internal server error", http.StatusInternalServerError)
	HTTPErrServiceUnavailable  = NewHTTPError(CodeUnavailable, "Service unavailable", http.StatusServiceUnavailable)
)

// errorToHTTPStatus maps errors to HTTP status codes
func errorToHTTPStatus(err error) int {
	switch {
	case Is(err, ErrNotFound):
		return http.StatusNotFound
	case Is(err, ErrAlreadyExists):
		return http.StatusConflict
	case Is(err, ErrInvalidArgument):
		return http.StatusBadRequest
	case Is(err, ErrInvalidOperation):
		return http.StatusBadRequest
	case Is(err, ErrUnauthenticated):
		return http.StatusUnauthorized
	case Is(err, ErrUnauthorized):
		return http.StatusForbidden
	case Is(err, ErrForbidden):
		return http.StatusForbidden
	case Is(err, ErrRateLimited):
		return http.StatusTooManyRequests
	case Is(err, ErrTimeout):
		return http.StatusGatewayTimeout
	case Is(err, ErrCanceled):
		return http.StatusRequestTimeout
	case Is(err, ErrServiceUnavailable):
		return http.StatusServiceUnavailable
	default:
		// Check if the error has a specific code
		code := GetErrorCode(err)
		switch code {
		case CodeNotFound:
			return http.StatusNotFound
		case CodeAlreadyExists:
			return http.StatusConflict
		case CodeInvalidArgument:
			return http.StatusBadRequest
		case CodeInvalidOperation:
			return http.StatusBadRequest
		case CodeUnauthenticated:
			return http.StatusUnauthorized
		case CodeUnauthorized:
			return http.StatusForbidden
		case CodeForbidden:
			return http.StatusForbidden
		case CodeRateLimited:
			return http.StatusTooManyRequests
		case CodeTimeout:
			return http.StatusGatewayTimeout
		case CodeCanceled:
			return http.StatusRequestTimeout
		case CodeUnavailable:
			return http.StatusServiceUnavailable
		default:
			return http.StatusInternalServerError
		}
	}
}

// WriteErrorResponse writes an error to the HTTP response
func WriteErrorResponse(w http.ResponseWriter, err error) {
	httpErr := ErrorToHTTP(err)
	httpErr.WriteResponse(w)
}

// WriteJSONError writes a JSON error to the HTTP response
func WriteJSONError(w http.ResponseWriter, code ErrorCode, message string, status int) {
	httpErr := NewHTTPError(code, message, status)
	httpErr.WriteResponse(w)
}