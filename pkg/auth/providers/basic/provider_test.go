package basic_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/auth/providers/basic"
	"github.com/Fishwaldo/auth2/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations
type mockUserStore struct {
	mock.Mock
}

func (m *mockUserStore) Create(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *mockUserStore) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *mockUserStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *mockUserStore) Update(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockUserStore) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockUserStore) List(ctx context.Context, filter map[string]interface{}, offset, limit int) ([]*user.User, error) {
	args := m.Called(ctx, filter, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*user.User), args.Error(1)
}

func (m *mockUserStore) Count(ctx context.Context, filter map[string]interface{}) (int, error) {
	args := m.Called(ctx, filter)
	return args.Int(0), args.Error(1)
}

type mockPasswordUtils struct {
	mock.Mock
}

func (m *mockPasswordUtils) HashPassword(ctx context.Context, password string) (string, error) {
	args := m.Called(ctx, password)
	return args.String(0), args.Error(1)
}

func (m *mockPasswordUtils) VerifyPassword(ctx context.Context, password, hash string) (bool, error) {
	args := m.Called(ctx, password, hash)
	return args.Bool(0), args.Error(1)
}

func (m *mockPasswordUtils) GeneratePassword(ctx context.Context, length int) (string, error) {
	args := m.Called(ctx, length)
	return args.String(0), args.Error(1)
}

func (m *mockPasswordUtils) GenerateResetToken(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *mockPasswordUtils) GenerateVerificationToken(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

// mockTimeProvider is a mock implementation of TimeProvider for testing
type mockTimeProvider struct {
	fixedTime time.Time
}

func (m *mockTimeProvider) Now() time.Time {
	return m.fixedTime
}

func TestNewProvider(t *testing.T) {
	userStore := &mockUserStore{}
	passwordUtils := &mockPasswordUtils{}
	
	t.Run("with config", func(t *testing.T) {
		config := &basic.Config{
			AccountLockThreshold: 3,
			AccountLockDuration:  60,
			RequireVerifiedEmail: false,
		}
		
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, config)
		
		assert.NotNil(t, provider)
		assert.Equal(t, "basic-auth", provider.GetMetadata().ID)
		assert.Equal(t, basic.ProviderName, provider.GetMetadata().Name)
		assert.Equal(t, basic.ProviderDescription, provider.GetMetadata().Description)
	})
	
	t.Run("with nil config", func(t *testing.T) {
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
		
		assert.NotNil(t, provider)
		// Should use default config
	})
}

func TestDefaultConfig(t *testing.T) {
	config := basic.DefaultConfig()
	
	assert.Equal(t, 5, config.AccountLockThreshold)
	assert.Equal(t, 30, config.AccountLockDuration)
	assert.True(t, config.RequireVerifiedEmail)
}

func TestProvider_Authenticate(t *testing.T) {
	tests := []struct {
		name          string
		credentials   interface{}
		setupMocks    func(*mockUserStore, *mockPasswordUtils)
		config        *basic.Config
		expectedError string
		checkResult   func(*testing.T, *providers.AuthResult)
	}{
		{
			name: "successful authentication",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:                  "user123",
					Username:            "testuser",
					PasswordHash:        "hashed_password",
					Enabled:             true,
					EmailVerified:       true,
					FailedLoginAttempts: 0,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(true, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 0 &&
						!u.LastLogin.IsZero()
				})).Return(nil)
			},
			checkResult: func(t *testing.T, result *providers.AuthResult) {
				assert.True(t, result.Success)
				assert.Equal(t, "user123", result.UserID)
				assert.False(t, result.RequiresMFA)
			},
		},
		{
			name: "invalid credentials type",
			credentials: "invalid",
			expectedError: "invalid credentials type",
			checkResult: func(t *testing.T, result *providers.AuthResult) {
				assert.False(t, result.Success)
				assert.Equal(t, "basic-auth", result.ProviderID)
			},
		},
		{
			name: "empty username",
			credentials: providers.UsernamePasswordCredentials{
				Username: "",
				Password: "password123",
			},
			expectedError: "username and password are required",
		},
		{
			name: "empty password",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "",
			},
			expectedError: "username and password are required",
		},
		{
			name: "user not found",
			credentials: providers.UsernamePasswordCredentials{
				Username: "nonexistent",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				store.On("GetByUsername", mock.Anything, "nonexistent").Return(nil, user.ErrUserNotFound)
			},
			expectedError: "user not found",
		},
		{
			name: "user disabled",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:       "user123",
					Username: "testuser",
					Enabled:  false,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
			},
			expectedError: "account is disabled",
		},
		{
			name: "user locked",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:       "user123",
					Username: "testuser",
					Enabled:  true,
					Locked:   true,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
			},
			expectedError: "account is locked",
		},
		{
			name: "email not verified",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			config: &basic.Config{
				RequireVerifiedEmail: true,
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:            "user123",
					Username:      "testuser",
					Enabled:       true,
					EmailVerified: false,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
			},
			expectedError: "email verification required",
		},
		{
			name: "invalid password",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "wrongpassword",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:                  "user123",
					Username:            "testuser",
					PasswordHash:        "hashed_password",
					Enabled:             true,
					EmailVerified:       true,
					FailedLoginAttempts: 2,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "wrongpassword", "hashed_password").Return(false, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 3 &&
						!u.LastFailedLogin.IsZero()
				})).Return(nil)
			},
			expectedError: "invalid credentials",
		},
		{
			name: "account locked after too many attempts",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "wrongpassword",
			},
			config: &basic.Config{
				AccountLockThreshold: 3,
				RequireVerifiedEmail: true,
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:                  "user123",
					Username:            "testuser",
					PasswordHash:        "hashed_password",
					Enabled:             true,
					EmailVerified:       true,
					FailedLoginAttempts: 2, // Next attempt will lock
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "wrongpassword", "hashed_password").Return(false, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 3 &&
						u.Locked == true &&
						!u.LockoutTime.IsZero() &&
						u.LockoutReason == "Too many failed login attempts"
				})).Return(nil)
			},
			expectedError: "invalid credentials",
		},
		{
			name: "authentication with MFA required",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:            "user123",
					Username:      "testuser",
					PasswordHash:  "hashed_password",
					Enabled:       true,
					EmailVerified: true,
					MFAEnabled:    true,
					MFAMethods:    []string{"totp", "webauthn"},
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(true, nil)
				store.On("Update", mock.Anything, mock.Anything).Return(nil)
			},
			checkResult: func(t *testing.T, result *providers.AuthResult) {
				assert.True(t, result.Success)
				assert.Equal(t, "user123", result.UserID)
				assert.True(t, result.RequiresMFA)
				assert.Equal(t, []string{"totp", "webauthn"}, result.MFAProviders)
			},
		},
		{
			name: "authentication with password change required",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:                    "user123",
					Username:              "testuser",
					PasswordHash:          "hashed_password",
					Enabled:               true,
					EmailVerified:         true,
					RequirePasswordChange: true,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(true, nil)
				store.On("Update", mock.Anything, mock.Anything).Return(nil)
			},
			checkResult: func(t *testing.T, result *providers.AuthResult) {
				assert.True(t, result.Success)
				assert.Equal(t, "user123", result.UserID)
				assert.True(t, result.Extra["require_password_change"].(bool))
			},
		},
		{
			name: "password verification error",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:            "user123",
					Username:      "testuser",
					PasswordHash:  "hashed_password",
					Enabled:       true,
					EmailVerified: true,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(false, errors.New("crypto error"))
			},
			expectedError: "password verification failed",
		},
		{
			name: "update user error after successful auth",
			credentials: providers.UsernamePasswordCredentials{
				Username: "testuser",
				Password: "password123",
			},
			setupMocks: func(store *mockUserStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:            "user123",
					Username:      "testuser",
					PasswordHash:  "hashed_password",
					Enabled:       true,
					EmailVerified: true,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(true, nil)
				store.On("Update", mock.Anything, mock.Anything).Return(errors.New("database error"))
			},
			checkResult: func(t *testing.T, result *providers.AuthResult) {
				// Should still succeed even if update fails
				assert.True(t, result.Success)
				assert.Equal(t, "user123", result.UserID)
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userStore := &mockUserStore{}
			passwordUtils := &mockPasswordUtils{}
			
			config := tt.config
			if config == nil {
				config = basic.DefaultConfig()
			}
			
			provider := basic.NewProvider("basic-auth", userStore, passwordUtils, config)
			
			if tt.setupMocks != nil {
				tt.setupMocks(userStore, passwordUtils)
			}
			
			authCtx := &providers.AuthContext{
				OriginalContext: context.Background(),
				RequestID:       "test-request",
				ClientIP:        "127.0.0.1",
				UserAgent:       "test-agent",
			}
			
			result, err := provider.Authenticate(authCtx, tt.credentials)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			if tt.checkResult != nil {
				tt.checkResult(t, result)
			}
			
			userStore.AssertExpectations(t)
			passwordUtils.AssertExpectations(t)
		})
	}
}

func TestProvider_Supports(t *testing.T) {
	userStore := &mockUserStore{}
	passwordUtils := &mockPasswordUtils{}
	provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
	
	t.Run("supports UsernamePasswordCredentials", func(t *testing.T) {
		creds := providers.UsernamePasswordCredentials{
			Username: "test",
			Password: "pass",
		}
		assert.True(t, provider.Supports(creds))
	})
	
	t.Run("does not support other types", func(t *testing.T) {
		assert.False(t, provider.Supports("string"))
		assert.False(t, provider.Supports(123))
		assert.False(t, provider.Supports(providers.TokenCredentials{TokenType: "bearer", TokenValue: "token"}))
	})
}

func TestProvider_Initialize(t *testing.T) {
	userStore := &mockUserStore{}
	passwordUtils := &mockPasswordUtils{}
	
	t.Run("initialize with Config struct", func(t *testing.T) {
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
		
		config := &basic.Config{
			AccountLockThreshold: 10,
			AccountLockDuration:  60,
			RequireVerifiedEmail: false,
		}
		
		err := provider.Initialize(context.Background(), config)
		assert.NoError(t, err)
		
		// Initialize again should be idempotent
		err = provider.Initialize(context.Background(), config)
		assert.NoError(t, err)
	})
	
	t.Run("initialize with map", func(t *testing.T) {
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
		
		configMap := map[string]interface{}{
			"account_lock_threshold":  7,
			"account_lock_duration":   45,
			"require_verified_email":  false,
		}
		
		err := provider.Initialize(context.Background(), configMap)
		assert.NoError(t, err)
	})
	
	t.Run("initialize with nil config", func(t *testing.T) {
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
		
		err := provider.Initialize(context.Background(), nil)
		assert.NoError(t, err)
	})
	
	t.Run("initialize with invalid config type", func(t *testing.T) {
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
		
		err := provider.Initialize(context.Background(), "invalid config")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid configuration type")
	})
}

func TestProvider_Validate(t *testing.T) {
	t.Run("valid provider", func(t *testing.T) {
		userStore := &mockUserStore{}
		passwordUtils := &mockPasswordUtils{}
		provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
		
		err := provider.Validate(context.Background())
		assert.NoError(t, err)
	})
	
	t.Run("missing user store", func(t *testing.T) {
		passwordUtils := &mockPasswordUtils{}
		provider := basic.NewProvider("basic-auth", nil, passwordUtils, nil)
		
		err := provider.Validate(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user store not set")
	})
	
	t.Run("missing password utils", func(t *testing.T) {
		userStore := &mockUserStore{}
		provider := basic.NewProvider("basic-auth", userStore, nil, nil)
		
		err := provider.Validate(context.Background())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password utilities not set")
	})
}

func TestProvider_IsCompatibleVersion(t *testing.T) {
	userStore := &mockUserStore{}
	passwordUtils := &mockPasswordUtils{}
	provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
	
	// This uses the base provider implementation
	assert.True(t, provider.IsCompatibleVersion("1.0.0"))
}

func TestProvider_trackFailedLoginAttempt(t *testing.T) {
	// Test update error handling
	userStore := &mockUserStore{}
	passwordUtils := &mockPasswordUtils{}
	
	config := &basic.Config{
		AccountLockThreshold: 3,
	}
	
	provider := basic.NewProvider("basic-auth", userStore, passwordUtils, config)
	
	testUser := &user.User{
		ID:                  "user123",
		Username:            "testuser",
		PasswordHash:        "hashed_password",
		Enabled:             true,
		EmailVerified:       true,
		FailedLoginAttempts: 2,
	}
	
	userStore.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
	passwordUtils.On("VerifyPassword", mock.Anything, "wrongpassword", "hashed_password").Return(false, nil)
	// Simulate update error
	userStore.On("Update", mock.Anything, mock.Anything).Return(errors.New("database error"))
	
	authCtx := &providers.AuthContext{
		OriginalContext: context.Background(),
	}
	
	result, err := provider.Authenticate(authCtx, providers.UsernamePasswordCredentials{
		Username: "testuser",
		Password: "wrongpassword",
	})
	
	// Should still return authentication error despite update failure
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")
	assert.False(t, result.Success)
	
	userStore.AssertExpectations(t)
	passwordUtils.AssertExpectations(t)
}

// Test time manipulation for consistent tests
func TestProvider_AuthenticateTimeManipulation(t *testing.T) {
	// Save original time provider
	originalProvider := providers.CurrentTimeProvider
	defer func() {
		providers.CurrentTimeProvider = originalProvider
	}()
	
	// Create mock time provider
	fixedTime := time.Date(2023, 5, 23, 12, 0, 0, 0, time.UTC)
	mockTimeProvider := &mockTimeProvider{fixedTime: fixedTime}
	providers.CurrentTimeProvider = mockTimeProvider
	
	userStore := &mockUserStore{}
	passwordUtils := &mockPasswordUtils{}
	provider := basic.NewProvider("basic-auth", userStore, passwordUtils, nil)
	
	testUser := &user.User{
		ID:            "user123",
		Username:      "testuser",
		PasswordHash:  "hashed_password",
		Enabled:       true,
		EmailVerified: true,
	}
	
	userStore.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
	passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(true, nil)
	userStore.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
		return u.LastLogin.Equal(fixedTime)
	})).Return(nil)
	
	authCtx := &providers.AuthContext{
		OriginalContext: context.Background(),
	}
	
	_, err := provider.Authenticate(authCtx, providers.UsernamePasswordCredentials{
		Username: "testuser",
		Password: "password123",
	})
	
	require.NoError(t, err)
	userStore.AssertExpectations(t)
}