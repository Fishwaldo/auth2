package errors_test

import (
	"errors"
	"fmt"
	"testing"

	interrors "github.com/Fishwaldo/auth2/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		code           string
		reason         string
		userID         string
		temporary      bool
		expectedError  string
	}{
		{
			name:          "basic auth error",
			err:           errors.New("test error"),
			code:          "AUTH001",
			reason:        "invalid credentials",
			userID:        "",
			temporary:     false,
			expectedError: "[AUTH001] test error: invalid credentials",
		},
		{
			name:          "auth error with user ID",
			err:           errors.New("access denied"),
			code:          "AUTH002",
			reason:        "insufficient permissions",
			userID:        "user123",
			temporary:     false,
			expectedError: "[AUTH002] access denied: insufficient permissions (user: user123)",
		},
		{
			name:          "temporary auth error",
			err:           errors.New("service unavailable"),
			code:          "AUTH003",
			reason:        "backend service down",
			userID:        "user456",
			temporary:     true,
			expectedError: "[AUTH003] service unavailable: backend service down (user: user456)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authErr := interrors.NewAuthError(tt.err, tt.code, tt.reason, tt.userID, tt.temporary)
			
			assert.Equal(t, tt.expectedError, authErr.Error())
			assert.Equal(t, tt.err, authErr.Unwrap())
			assert.Equal(t, tt.code, authErr.Code)
			assert.Equal(t, tt.reason, authErr.Reason)
			assert.Equal(t, tt.userID, authErr.UserID)
			assert.Equal(t, tt.temporary, authErr.Temporary)
		})
	}
}

func TestIsAuthError(t *testing.T) {
	authErr := interrors.NewAuthError(errors.New("test"), "AUTH001", "test reason", "user123", false)
	wrappedErr := fmt.Errorf("wrapped: %w", authErr)
	plainErr := errors.New("plain error")

	assert.True(t, interrors.IsAuthError(authErr))
	assert.True(t, interrors.IsAuthError(wrappedErr))
	assert.False(t, interrors.IsAuthError(plainErr))
	assert.False(t, interrors.IsAuthError(nil))
}

func TestGetAuthError(t *testing.T) {
	authErr := interrors.NewAuthError(errors.New("test"), "AUTH001", "test reason", "user123", false)
	wrappedErr := fmt.Errorf("wrapped: %w", authErr)
	plainErr := errors.New("plain error")

	// Test with AuthError
	extracted, ok := interrors.GetAuthError(authErr)
	assert.True(t, ok)
	assert.Equal(t, authErr, extracted)

	// Test with wrapped AuthError
	extracted, ok = interrors.GetAuthError(wrappedErr)
	assert.True(t, ok)
	assert.Equal(t, authErr, extracted)

	// Test with plain error
	extracted, ok = interrors.GetAuthError(plainErr)
	assert.False(t, ok)
	assert.Nil(t, extracted)

	// Test with nil
	extracted, ok = interrors.GetAuthError(nil)
	assert.False(t, ok)
	assert.Nil(t, extracted)
}

func TestPluginError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		pluginType     string
		pluginName     string
		description    string
		expectedError  string
	}{
		{
			name:          "basic plugin error",
			err:           errors.New("initialization failed"),
			pluginType:    "auth",
			pluginName:    "oauth2",
			description:   "failed to load configuration",
			expectedError: "plugin error [auth - oauth2]: initialization failed: failed to load configuration",
		},
		{
			name:          "storage plugin error",
			err:           errors.New("connection timeout"),
			pluginType:    "storage",
			pluginName:    "postgres",
			description:   "database connection failed",
			expectedError: "plugin error [storage - postgres]: connection timeout: database connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pluginErr := interrors.NewPluginError(tt.err, tt.pluginType, tt.pluginName, tt.description)
			
			assert.Equal(t, tt.expectedError, pluginErr.Error())
			assert.Equal(t, tt.err, pluginErr.Unwrap())
			assert.Equal(t, tt.pluginType, pluginErr.PluginType)
			assert.Equal(t, tt.pluginName, pluginErr.PluginName)
			assert.Equal(t, tt.description, pluginErr.Description)
		})
	}
}

func TestIsPluginError(t *testing.T) {
	pluginErr := interrors.NewPluginError(errors.New("test"), "auth", "test", "description")
	wrappedErr := fmt.Errorf("wrapped: %w", pluginErr)
	plainErr := errors.New("plain error")

	assert.True(t, interrors.IsPluginError(pluginErr))
	assert.True(t, interrors.IsPluginError(wrappedErr))
	assert.False(t, interrors.IsPluginError(plainErr))
	assert.False(t, interrors.IsPluginError(nil))
}

func TestGetPluginError(t *testing.T) {
	pluginErr := interrors.NewPluginError(errors.New("test"), "auth", "test", "description")
	wrappedErr := fmt.Errorf("wrapped: %w", pluginErr)
	plainErr := errors.New("plain error")

	// Test with PluginError
	extracted, ok := interrors.GetPluginError(pluginErr)
	assert.True(t, ok)
	assert.Equal(t, pluginErr, extracted)

	// Test with wrapped PluginError
	extracted, ok = interrors.GetPluginError(wrappedErr)
	assert.True(t, ok)
	assert.Equal(t, pluginErr, extracted)

	// Test with plain error
	extracted, ok = interrors.GetPluginError(plainErr)
	assert.False(t, ok)
	assert.Nil(t, extracted)

	// Test with nil
	extracted, ok = interrors.GetPluginError(nil)
	assert.False(t, ok)
	assert.Nil(t, extracted)
}

func TestValidationError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		field          string
		value          interface{}
		constraint     string
		expectedError  string
	}{
		{
			name:          "string validation error",
			err:           errors.New("too short"),
			field:         "username",
			value:         "ab",
			constraint:    "minimum length 3",
			expectedError: "validation error [username]: too short (got: ab, constraint: minimum length 3)",
		},
		{
			name:          "numeric validation error",
			err:           errors.New("out of range"),
			field:         "age",
			value:         150,
			constraint:    "0 <= age <= 120",
			expectedError: "validation error [age]: out of range (got: 150, constraint: 0 <= age <= 120)",
		},
		{
			name:          "nil value validation error",
			err:           errors.New("required"),
			field:         "email",
			value:         nil,
			constraint:    "not null",
			expectedError: "validation error [email]: required (got: <nil>, constraint: not null)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validationErr := interrors.NewValidationError(tt.err, tt.field, tt.value, tt.constraint)
			
			assert.Equal(t, tt.expectedError, validationErr.Error())
			assert.Equal(t, tt.err, validationErr.Unwrap())
			assert.Equal(t, tt.field, validationErr.Field)
			assert.Equal(t, tt.value, validationErr.Value)
			assert.Equal(t, tt.constraint, validationErr.Constraint)
		})
	}
}

func TestIsValidationError(t *testing.T) {
	validationErr := interrors.NewValidationError(errors.New("test"), "field", "value", "constraint")
	wrappedErr := fmt.Errorf("wrapped: %w", validationErr)
	plainErr := errors.New("plain error")

	assert.True(t, interrors.IsValidationError(validationErr))
	assert.True(t, interrors.IsValidationError(wrappedErr))
	assert.False(t, interrors.IsValidationError(plainErr))
	assert.False(t, interrors.IsValidationError(nil))
}

func TestGetValidationError(t *testing.T) {
	validationErr := interrors.NewValidationError(errors.New("test"), "field", "value", "constraint")
	wrappedErr := fmt.Errorf("wrapped: %w", validationErr)
	plainErr := errors.New("plain error")

	// Test with ValidationError
	extracted, ok := interrors.GetValidationError(validationErr)
	assert.True(t, ok)
	assert.Equal(t, validationErr, extracted)

	// Test with wrapped ValidationError
	extracted, ok = interrors.GetValidationError(wrappedErr)
	assert.True(t, ok)
	assert.Equal(t, validationErr, extracted)

	// Test with plain error
	extracted, ok = interrors.GetValidationError(plainErr)
	assert.False(t, ok)
	assert.Nil(t, extracted)

	// Test with nil
	extracted, ok = interrors.GetValidationError(nil)
	assert.False(t, ok)
	assert.Nil(t, extracted)
}

func TestStorageError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		storageType    string
		entity         string
		operation      string
		expectedError  string
	}{
		{
			name:          "SQL storage error",
			err:           errors.New("constraint violation"),
			storageType:   "sql",
			entity:        "users",
			operation:     "insert",
			expectedError: "storage error [sql - users - insert]: constraint violation",
		},
		{
			name:          "memory storage error",
			err:           errors.New("not found"),
			storageType:   "memory",
			entity:        "sessions",
			operation:     "get",
			expectedError: "storage error [memory - sessions - get]: not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageErr := interrors.NewStorageError(tt.err, tt.storageType, tt.entity, tt.operation)
			
			assert.Equal(t, tt.expectedError, storageErr.Error())
			assert.Equal(t, tt.err, storageErr.Unwrap())
			assert.Equal(t, tt.storageType, storageErr.StorageType)
			assert.Equal(t, tt.entity, storageErr.Entity)
			assert.Equal(t, tt.operation, storageErr.Operation)
		})
	}
}

func TestIsStorageError(t *testing.T) {
	storageErr := interrors.NewStorageError(errors.New("test"), "sql", "users", "insert")
	wrappedErr := fmt.Errorf("wrapped: %w", storageErr)
	plainErr := errors.New("plain error")

	assert.True(t, interrors.IsStorageError(storageErr))
	assert.True(t, interrors.IsStorageError(wrappedErr))
	assert.False(t, interrors.IsStorageError(plainErr))
	assert.False(t, interrors.IsStorageError(nil))
}

func TestGetStorageError(t *testing.T) {
	storageErr := interrors.NewStorageError(errors.New("test"), "sql", "users", "insert")
	wrappedErr := fmt.Errorf("wrapped: %w", storageErr)
	plainErr := errors.New("plain error")

	// Test with StorageError
	extracted, ok := interrors.GetStorageError(storageErr)
	assert.True(t, ok)
	assert.Equal(t, storageErr, extracted)

	// Test with wrapped StorageError
	extracted, ok = interrors.GetStorageError(wrappedErr)
	assert.True(t, ok)
	assert.Equal(t, storageErr, extracted)

	// Test with plain error
	extracted, ok = interrors.GetStorageError(plainErr)
	assert.False(t, ok)
	assert.Nil(t, extracted)

	// Test with nil
	extracted, ok = interrors.GetStorageError(nil)
	assert.False(t, ok)
	assert.Nil(t, extracted)
}

func TestStandardErrors(t *testing.T) {
	// Test that all standard errors are defined
	standardErrors := []struct {
		name string
		err  error
	}{
		// General errors
		{"ErrInternal", interrors.ErrInternal},
		{"ErrNotImplemented", interrors.ErrNotImplemented},
		{"ErrInvalidArgument", interrors.ErrInvalidArgument},
		{"ErrInvalidOperation", interrors.ErrInvalidOperation},
		
		// Authentication errors
		{"ErrAuthFailed", interrors.ErrAuthFailed},
		{"ErrInvalidCredentials", interrors.ErrInvalidCredentials},
		{"ErrUserNotFound", interrors.ErrUserNotFound},
		{"ErrUserDisabled", interrors.ErrUserDisabled},
		{"ErrUserLocked", interrors.ErrUserLocked},
		
		// MFA errors
		{"ErrMFARequired", interrors.ErrMFARequired},
		{"ErrMFAFailed", interrors.ErrMFAFailed},
		{"ErrMFANotEnabled", interrors.ErrMFANotEnabled},
		{"ErrInvalidMFACode", interrors.ErrInvalidMFACode},
		
		// Session errors
		{"ErrSessionExpired", interrors.ErrSessionExpired},
		{"ErrInvalidSession", interrors.ErrInvalidSession},
		{"ErrSessionNotFound", interrors.ErrSessionNotFound},
		
		// Token errors
		{"ErrInvalidToken", interrors.ErrInvalidToken},
		{"ErrTokenExpired", interrors.ErrTokenExpired},
		
		// Permission errors
		{"ErrPermissionDenied", interrors.ErrPermissionDenied},
		{"ErrRoleNotFound", interrors.ErrRoleNotFound},
		
		// Rate limiting errors
		{"ErrRateLimitExceeded", interrors.ErrRateLimitExceeded},
		
		// Plugin errors
		{"ErrPluginNotFound", interrors.ErrPluginNotFound},
		{"ErrIncompatiblePlugin", interrors.ErrIncompatiblePlugin},
		{"ErrProviderExists", interrors.ErrProviderExists},
	}

	for _, tt := range standardErrors {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotNil(t, tt.err)
			assert.Error(t, tt.err)
		})
	}
}

func TestErrorIs(t *testing.T) {
	// Test Is function
	assert.True(t, interrors.Is(interrors.ErrUserNotFound, interrors.ErrUserNotFound))
	assert.False(t, interrors.Is(interrors.ErrUserNotFound, interrors.ErrUserDisabled))
	
	// Test with wrapped errors
	wrappedErr := fmt.Errorf("wrapped: %w", interrors.ErrUserNotFound)
	assert.True(t, interrors.Is(wrappedErr, interrors.ErrUserNotFound))
}

func TestErrorAs(t *testing.T) {
	authErr := interrors.NewAuthError(errors.New("test"), "AUTH001", "test", "", false)
	wrappedErr := fmt.Errorf("wrapped: %w", authErr)
	
	// Test As function
	var target *interrors.AuthError
	assert.True(t, interrors.As(authErr, &target))
	assert.Equal(t, authErr, target)
	
	// Test with wrapped error
	var target2 *interrors.AuthError
	assert.True(t, interrors.As(wrappedErr, &target2))
	assert.Equal(t, authErr, target2)
	
	// Test with wrong type
	var wrongTarget *interrors.PluginError
	assert.False(t, interrors.As(authErr, &wrongTarget))
}

func TestNew(t *testing.T) {
	err := interrors.New("test error")
	assert.Error(t, err)
	assert.Equal(t, "test error", err.Error())
}

func TestNewInternalError(t *testing.T) {
	err := interrors.NewInternalError("something went wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "something went wrong")
	assert.True(t, interrors.Is(err, interrors.ErrInternal))
}

func TestWrap(t *testing.T) {
	// Test wrapping an error
	baseErr := errors.New("base error")
	wrappedErr := interrors.Wrap(baseErr, "additional context")
	
	assert.Error(t, wrappedErr)
	assert.Contains(t, wrappedErr.Error(), "additional context")
	assert.Contains(t, wrappedErr.Error(), "base error")
	assert.True(t, errors.Is(wrappedErr, baseErr))
	
	// Test wrapping nil
	nilWrapped := interrors.Wrap(nil, "context")
	assert.Nil(t, nilWrapped)
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		v1       string
		v2       string
		expected int
		wantErr  bool
	}{
		{
			name:     "v1 less than v2 - major",
			v1:       "1.0.0",
			v2:       "2.0.0",
			expected: -1,
			wantErr:  false,
		},
		{
			name:     "v1 less than v2 - minor",
			v1:       "1.1.0",
			v2:       "1.2.0",
			expected: -1,
			wantErr:  false,
		},
		{
			name:     "v1 less than v2 - patch",
			v1:       "1.1.1",
			v2:       "1.1.2",
			expected: -1,
			wantErr:  false,
		},
		{
			name:     "v1 equals v2",
			v1:       "1.2.3",
			v2:       "1.2.3",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "v1 greater than v2 - major",
			v1:       "2.0.0",
			v2:       "1.0.0",
			expected: 1,
			wantErr:  false,
		},
		{
			name:     "v1 greater than v2 - minor",
			v1:       "1.2.0",
			v2:       "1.1.0",
			expected: 1,
			wantErr:  false,
		},
		{
			name:     "v1 greater than v2 - patch",
			v1:       "1.1.2",
			v2:       "1.1.1",
			expected: 1,
			wantErr:  false,
		},
		{
			name:     "versions with pre-release ignored",
			v1:       "1.2.3-beta",
			v2:       "1.2.3-alpha",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "short version format - v1",
			v1:       "1.2",
			v2:       "1.2.0",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "short version format - v2",
			v1:       "1.2.0",
			v2:       "1.2",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "invalid v1 format",
			v1:       "1.a.0",
			v2:       "1.2.0",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid v2 format",
			v1:       "1.2.0",
			v2:       "1.b.0",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "single digit versions",
			v1:       "1",
			v2:       "2",
			expected: -1,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := interrors.CompareVersions(tt.v1, tt.v2)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}