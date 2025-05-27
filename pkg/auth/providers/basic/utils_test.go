package basic_test

import (
	"context"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/auth/providers/basic"
	"github.com/Fishwaldo/auth2/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestValidateAccount(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		user          *user.User
		config        *basic.Config
		expectError   bool
		errorContains string
	}{
		{
			name: "valid account",
			user: &user.User{
				Enabled:       true,
				Locked:        false,
				EmailVerified: true,
			},
			config: &basic.Config{
				RequireVerifiedEmail: true,
			},
			expectError: false,
		},
		{
			name: "disabled account",
			user: &user.User{
				Enabled: false,
			},
			config:        &basic.Config{},
			expectError:   true,
			errorContains: "account is disabled",
		},
		{
			name: "locked account - no expiry",
			user: &user.User{
				Enabled: true,
				Locked:  true,
			},
			config: &basic.Config{
				AccountLockDuration: 0,
			},
			expectError:   true,
			errorContains: "account is locked",
		},
		{
			name: "locked account - not expired",
			user: &user.User{
				Enabled:     true,
				Locked:      true,
				LockoutTime: time.Now().Add(-5 * time.Minute),
			},
			config: &basic.Config{
				AccountLockDuration: 30, // 30 minutes
			},
			expectError:   true,
			errorContains: "account is locked",
		},
		{
			name: "locked account - expired",
			user: &user.User{
				Enabled:     true,
				Locked:      true,
				LockoutTime: time.Now().Add(-60 * time.Minute),
			},
			config: &basic.Config{
				AccountLockDuration: 30, // 30 minutes
			},
			expectError: false,
		},
		{
			name: "unverified email when required",
			user: &user.User{
				Enabled:       true,
				Locked:        false,
				EmailVerified: false,
			},
			config: &basic.Config{
				RequireVerifiedEmail: true,
			},
			expectError:   true,
			errorContains: "email verification required",
		},
		{
			name: "unverified email when not required",
			user: &user.User{
				Enabled:       true,
				Locked:        false,
				EmailVerified: false,
			},
			config: &basic.Config{
				RequireVerifiedEmail: false,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := basic.ValidateAccount(ctx, tt.user, tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckPasswordRequirements(t *testing.T) {
	tests := []struct {
		name           string
		user           *user.User
		expectRequired bool
		expectReason   string
	}{
		{
			name: "password change required",
			user: &user.User{
				RequirePasswordChange: true,
			},
			expectRequired: true,
			expectReason:   "Password change required",
		},
		{
			name: "password change not required",
			user: &user.User{
				RequirePasswordChange: false,
			},
			expectRequired: false,
			expectReason:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			required, reason := basic.CheckPasswordRequirements(tt.user)
			
			assert.Equal(t, tt.expectRequired, required)
			assert.Equal(t, tt.expectReason, reason)
		})
	}
}

func TestProcessSuccessfulLogin(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockUserStore{}
	
	originalTime := time.Now()
	usr := &user.User{
		ID:                  "user123",
		FailedLoginAttempts: 5,
		LastLogin:           originalTime.Add(-24 * time.Hour),
	}

	// Set up expectation
	mockStore.On("Update", ctx, mock.MatchedBy(func(u *user.User) bool {
		return u.ID == usr.ID && 
			u.FailedLoginAttempts == 0 && 
			u.LastLogin.After(originalTime)
	})).Return(nil)

	err := basic.ProcessSuccessfulLogin(ctx, mockStore, usr)
	
	assert.NoError(t, err)
	assert.Equal(t, 0, usr.FailedLoginAttempts)
	assert.True(t, usr.LastLogin.After(originalTime))
	
	mockStore.AssertExpectations(t)
}

func TestProcessSuccessfulLogin_UpdateError(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockUserStore{}
	
	usr := &user.User{
		ID:                  "user123",
		FailedLoginAttempts: 5,
	}

	// Set up expectation for error
	expectedErr := assert.AnError
	mockStore.On("Update", ctx, mock.AnythingOfType("*user.User")).Return(expectedErr)

	err := basic.ProcessSuccessfulLogin(ctx, mockStore, usr)
	
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	
	mockStore.AssertExpectations(t)
}

func TestProcessFailedLogin(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name         string
		initialUser  *user.User
		config       *basic.Config
		setupMock    func(*mockUserStore)
		expectLocked bool
		expectError  bool
	}{
		{
			name: "increment failed attempts - not locked",
			initialUser: &user.User{
				ID:                  "user123",
				FailedLoginAttempts: 2,
			},
			config: &basic.Config{
				AccountLockThreshold: 5,
			},
			setupMock: func(m *mockUserStore) {
				m.On("Update", ctx, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 3 && 
						!u.Locked
				})).Return(nil)
			},
			expectLocked: false,
			expectError:  false,
		},
		{
			name: "increment failed attempts - lock account",
			initialUser: &user.User{
				ID:                  "user123",
				FailedLoginAttempts: 4,
			},
			config: &basic.Config{
				AccountLockThreshold: 5,
			},
			setupMock: func(m *mockUserStore) {
				m.On("Update", ctx, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 5 && 
						u.Locked &&
						!u.LockoutTime.IsZero() &&
						u.LockoutReason == "Too many failed login attempts"
				})).Return(nil)
			},
			expectLocked: true,
			expectError:  false,
		},
		{
			name: "no lock threshold",
			initialUser: &user.User{
				ID:                  "user123",
				FailedLoginAttempts: 10,
			},
			config: &basic.Config{
				AccountLockThreshold: 0,
			},
			setupMock: func(m *mockUserStore) {
				m.On("Update", ctx, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 11 && 
						!u.Locked
				})).Return(nil)
			},
			expectLocked: false,
			expectError:  false,
		},
		{
			name: "update error",
			initialUser: &user.User{
				ID:                  "user123",
				FailedLoginAttempts: 0,
			},
			config: &basic.Config{
				AccountLockThreshold: 5,
			},
			setupMock: func(m *mockUserStore) {
				m.On("Update", ctx, mock.AnythingOfType("*user.User")).Return(assert.AnError)
			},
			expectLocked: false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &mockUserStore{}
			tt.setupMock(mockStore)
			
			originalTime := time.Now()
			err := basic.ProcessFailedLogin(ctx, mockStore, tt.initialUser, tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.True(t, tt.initialUser.LastFailedLogin.After(originalTime) || 
					tt.initialUser.LastFailedLogin.Equal(originalTime))
				
				if tt.expectLocked {
					assert.True(t, tt.initialUser.Locked)
					assert.False(t, tt.initialUser.LockoutTime.IsZero())
					assert.Equal(t, "Too many failed login attempts", tt.initialUser.LockoutReason)
				} else {
					assert.False(t, tt.initialUser.Locked)
				}
			}
			
			mockStore.AssertExpectations(t)
		})
	}
}