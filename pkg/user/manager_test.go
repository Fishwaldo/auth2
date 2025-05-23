package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations
type mockStore struct {
	mock.Mock
}

func (m *mockStore) Create(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockStore) GetByID(ctx context.Context, id string) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *mockStore) GetByUsername(ctx context.Context, username string) (*user.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *mockStore) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *mockStore) Update(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockStore) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *mockStore) List(ctx context.Context, filter map[string]interface{}, offset, limit int) ([]*user.User, error) {
	args := m.Called(ctx, filter, offset, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*user.User), args.Error(1)
}

func (m *mockStore) Count(ctx context.Context, filter map[string]interface{}) (int, error) {
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

type mockProfileStore struct {
	mock.Mock
}

func (m *mockProfileStore) GetProfile(ctx context.Context, userID string) (map[string]interface{}, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *mockProfileStore) UpdateProfile(ctx context.Context, userID string, profile map[string]interface{}) error {
	args := m.Called(ctx, userID, profile)
	return args.Error(0)
}

type mockValidator struct {
	mock.Mock
}

func (m *mockValidator) ValidateNewUser(ctx context.Context, user *user.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func (m *mockValidator) ValidateUserUpdate(ctx context.Context, user *user.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *mockValidator) ValidatePassword(ctx context.Context, user *user.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func TestNewManager(t *testing.T) {
	store := &mockStore{}
	passwordUtils := &mockPasswordUtils{}
	profileStore := &mockProfileStore{}
	
	manager := user.NewManager(store, passwordUtils, profileStore)
	
	assert.NotNil(t, manager)
}

func TestManager_AddValidator(t *testing.T) {
	store := &mockStore{}
	passwordUtils := &mockPasswordUtils{}
	profileStore := &mockProfileStore{}
	
	manager := user.NewManager(store, passwordUtils, profileStore)
	
	validator := &mockValidator{}
	manager.AddValidator(validator)
	
	// Test that validator is used during registration
	ctx := context.Background()
	testUser := &user.User{
		Username: "testuser",
		Email:    "test@example.com",
	}
	
	validator.On("ValidateNewUser", ctx, mock.MatchedBy(func(u *user.User) bool {
		return u.Username == testUser.Username && u.Email == testUser.Email
	}), "password123").Return(errors.New("validation failed"))
	
	_, err := manager.Register(ctx, testUser.Username, testUser.Email, "password123")
	assert.Error(t, err)
	assert.Equal(t, "validation failed", err.Error())
	
	validator.AssertExpectations(t)
}

func TestManager_Register(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		email         string
		password      string
		setupMocks    func(*mockStore, *mockPasswordUtils, *mockValidator)
		useValidator  bool
		expectedError string
		validate      func(*testing.T, *user.User, error)
	}{
		{
			name:     "successful registration without validator",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				passwordUtils.On("HashPassword", mock.Anything, "password123").Return("hashed_password", nil)
				store.On("Create", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.Username == "testuser" &&
						u.Email == "test@example.com" &&
						u.PasswordHash == "hashed_password" &&
						u.Enabled == true &&
						!u.Locked &&
						!u.EmailVerified &&
						!u.MFAEnabled &&
						len(u.Profile) == 0 &&
						len(u.Metadata) == 0
				})).Return(nil)
			},
			validate: func(t *testing.T, u *user.User, err error) {
				require.NoError(t, err)
				assert.NotNil(t, u)
				assert.Equal(t, "testuser", u.Username)
				assert.Equal(t, "test@example.com", u.Email)
				assert.Equal(t, "hashed_password", u.PasswordHash)
				assert.True(t, u.Enabled)
				assert.False(t, u.Locked)
				assert.NotZero(t, u.CreatedAt)
				assert.NotZero(t, u.UpdatedAt)
			},
		},
		{
			name:     "successful registration with validator",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			useValidator: true,
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				validator.On("ValidateNewUser", mock.Anything, mock.Anything, "password123").Return(nil)
				passwordUtils.On("HashPassword", mock.Anything, "password123").Return("hashed_password", nil)
				store.On("Create", mock.Anything, mock.Anything).Return(nil)
			},
			validate: func(t *testing.T, u *user.User, err error) {
				require.NoError(t, err)
				assert.NotNil(t, u)
			},
		},
		{
			name:     "validation fails",
			username: "testuser",
			email:    "test@example.com",
			password: "weak",
			useValidator: true,
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				validator.On("ValidateNewUser", mock.Anything, mock.Anything, "weak").Return(errors.New("password too weak"))
			},
			expectedError: "password too weak",
		},
		{
			name:     "password hashing fails",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				passwordUtils.On("HashPassword", mock.Anything, "password123").Return("", errors.New("hashing failed"))
			},
			expectedError: "hashing failed",
		},
		{
			name:     "store creation fails",
			username: "testuser",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				passwordUtils.On("HashPassword", mock.Anything, "password123").Return("hashed_password", nil)
				store.On("Create", mock.Anything, mock.Anything).Return(errors.New("database error"))
			},
			expectedError: "database error",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			validator := &mockValidator{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			if tt.useValidator {
				manager.AddValidator(validator)
			}
			
			if tt.setupMocks != nil {
				tt.setupMocks(store, passwordUtils, validator)
			}
			
			ctx := context.Background()
			result, err := manager.Register(ctx, tt.username, tt.email, tt.password)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else if tt.validate != nil {
				tt.validate(t, result, err)
			}
			
			store.AssertExpectations(t)
			passwordUtils.AssertExpectations(t)
			if tt.useValidator {
				validator.AssertExpectations(t)
			}
		})
	}
}

func TestManager_Authenticate(t *testing.T) {
	tests := []struct {
		name          string
		username      string
		password      string
		setupMocks    func(*mockStore, *mockPasswordUtils)
		expectedError string
		validate      func(*testing.T, *user.User, error)
	}{
		{
			name:     "successful authentication",
			username: "testuser",
			password: "password123",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:           "user123",
					Username:     "testuser",
					PasswordHash: "hashed_password",
					Enabled:      true,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "password123", "hashed_password").Return(true, nil)
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && u.FailedLoginAttempts == 0 && !u.LastLogin.IsZero()
				})).Return(nil)
			},
			validate: func(t *testing.T, u *user.User, err error) {
				require.NoError(t, err)
				assert.NotNil(t, u)
				assert.Equal(t, "user123", u.ID)
				assert.Equal(t, "testuser", u.Username)
			},
		},
		{
			name:     "user not found",
			username: "nonexistent",
			password: "password123",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				store.On("GetByUsername", mock.Anything, "nonexistent").Return(nil, errors.New("user not found"))
			},
			expectedError: "user not found",
		},
		{
			name:     "invalid password",
			username: "testuser",
			password: "wrongpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:                  "user123",
					Username:            "testuser",
					PasswordHash:        "hashed_password",
					FailedLoginAttempts: 2,
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "wrongpassword", "hashed_password").Return(false, nil)
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && u.FailedLoginAttempts == 3 && !u.LastFailedLogin.IsZero()
				})).Return(nil)
			},
			expectedError: "invalid credentials",
		},
		{
			name:     "account locked after too many attempts",
			username: "testuser",
			password: "wrongpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:                  "user123",
					Username:            "testuser",
					PasswordHash:        "hashed_password",
					FailedLoginAttempts: 4, // One more attempt will lock
				}
				store.On("GetByUsername", mock.Anything, "testuser").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "wrongpassword", "hashed_password").Return(false, nil)
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 5 && 
						u.Locked == true &&
						!u.LockoutTime.IsZero() &&
						u.LockoutReason == "Too many failed login attempts"
				})).Return(nil)
			},
			expectedError: "invalid credentials",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			
			if tt.setupMocks != nil {
				tt.setupMocks(store, passwordUtils)
			}
			
			ctx := context.Background()
			result, err := manager.Authenticate(ctx, tt.username, tt.password)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else if tt.validate != nil {
				tt.validate(t, result, err)
			}
			
			store.AssertExpectations(t)
			passwordUtils.AssertExpectations(t)
		})
	}
}

func TestManager_GetUser(t *testing.T) {
	store := &mockStore{}
	passwordUtils := &mockPasswordUtils{}
	profileStore := &mockProfileStore{}
	
	manager := user.NewManager(store, passwordUtils, profileStore)
	
	testUser := &user.User{
		ID:       "user123",
		Username: "testuser",
		Email:    "test@example.com",
	}
	
	store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
	
	ctx := context.Background()
	result, err := manager.GetUser(ctx, "user123")
	
	require.NoError(t, err)
	assert.Equal(t, testUser, result)
	
	store.AssertExpectations(t)
}

func TestManager_UpdateUser(t *testing.T) {
	tests := []struct {
		name          string
		user          *user.User
		setupMocks    func(*mockStore, *mockValidator)
		useValidator  bool
		expectedError string
	}{
		{
			name: "successful update without validator",
			user: &user.User{
				ID:       "user123",
				Username: "testuser",
				Email:    "test@example.com",
			},
			setupMocks: func(store *mockStore, validator *mockValidator) {
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && !u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name: "validation fails",
			user: &user.User{
				ID:       "user123",
				Username: "testuser",
				Email:    "invalid-email",
			},
			useValidator: true,
			setupMocks: func(store *mockStore, validator *mockValidator) {
				validator.On("ValidateUserUpdate", mock.Anything, mock.Anything).Return(errors.New("invalid email format"))
			},
			expectedError: "invalid email format",
		},
		{
			name: "store update fails",
			user: &user.User{
				ID:       "user123",
				Username: "testuser",
				Email:    "test@example.com",
			},
			setupMocks: func(store *mockStore, validator *mockValidator) {
				store.On("Update", mock.Anything, mock.Anything).Return(errors.New("database error"))
			},
			expectedError: "database error",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			validator := &mockValidator{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			if tt.useValidator {
				manager.AddValidator(validator)
			}
			
			if tt.setupMocks != nil {
				tt.setupMocks(store, validator)
			}
			
			ctx := context.Background()
			err := manager.UpdateUser(ctx, tt.user)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
			if tt.useValidator {
				validator.AssertExpectations(t)
			}
		})
	}
}

func TestManager_ChangePassword(t *testing.T) {
	tests := []struct {
		name            string
		userID          string
		currentPassword string
		newPassword     string
		setupMocks      func(*mockStore, *mockPasswordUtils, *mockValidator)
		useValidator    bool
		expectedError   string
	}{
		{
			name:            "successful password change without validator",
			userID:          "user123",
			currentPassword: "oldpassword",
			newPassword:     "newpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				testUser := &user.User{
					ID:                    "user123",
					PasswordHash:          "old_hash",
					RequirePasswordChange: true,
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "oldpassword", "old_hash").Return(true, nil)
				passwordUtils.On("HashPassword", mock.Anything, "newpassword").Return("new_hash", nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.PasswordHash == "new_hash" && 
						!u.RequirePasswordChange &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:            "user not found",
			userID:          "nonexistent",
			currentPassword: "oldpassword",
			newPassword:     "newpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				store.On("GetByID", mock.Anything, "nonexistent").Return(nil, errors.New("user not found"))
			},
			expectedError: "user not found",
		},
		{
			name:            "current password incorrect",
			userID:          "user123",
			currentPassword: "wrongpassword",
			newPassword:     "newpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				testUser := &user.User{
					ID:           "user123",
					PasswordHash: "old_hash",
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "wrongpassword", "old_hash").Return(false, nil)
			},
			expectedError: "invalid credentials",
		},
		{
			name:            "new password validation fails",
			userID:          "user123",
			currentPassword: "oldpassword",
			newPassword:     "weak",
			useValidator:    true,
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				testUser := &user.User{
					ID:           "user123",
					PasswordHash: "old_hash",
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				passwordUtils.On("VerifyPassword", mock.Anything, "oldpassword", "old_hash").Return(true, nil)
				validator.On("ValidatePassword", mock.Anything, testUser, "weak").Return(errors.New("password too weak"))
			},
			expectedError: "password too weak",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			validator := &mockValidator{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			if tt.useValidator {
				manager.AddValidator(validator)
			}
			
			if tt.setupMocks != nil {
				tt.setupMocks(store, passwordUtils, validator)
			}
			
			ctx := context.Background()
			err := manager.ChangePassword(ctx, tt.userID, tt.currentPassword, tt.newPassword)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
			passwordUtils.AssertExpectations(t)
			if tt.useValidator {
				validator.AssertExpectations(t)
			}
		})
	}
}

func TestManager_ResetPassword(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		token         string
		newPassword   string
		setupMocks    func(*mockStore, *mockPasswordUtils, *mockValidator)
		useValidator  bool
		expectedError string
	}{
		{
			name:        "successful password reset without validator",
			userID:      "user123",
			token:       "valid_token",
			newPassword: "newpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				expiry := time.Now().Add(1 * time.Hour).Unix()
				testUser := &user.User{
					ID:           "user123",
					PasswordHash: "old_hash",
					Metadata: map[string]interface{}{
						"password_reset_token":  "valid_token",
						"password_reset_expiry": expiry,
					},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				passwordUtils.On("HashPassword", mock.Anything, "newpassword").Return("new_hash", nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					_, hasToken := u.Metadata["password_reset_token"]
					_, hasExpiry := u.Metadata["password_reset_expiry"]
					return u.ID == "user123" && 
						u.PasswordHash == "new_hash" && 
						!hasToken && !hasExpiry &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:        "successful password reset with validator",
			userID:      "user123",
			token:       "valid_token",
			newPassword: "newpassword",
			useValidator: true,
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				expiry := time.Now().Add(1 * time.Hour).Unix()
				testUser := &user.User{
					ID:           "user123",
					PasswordHash: "old_hash",
					Metadata: map[string]interface{}{
						"password_reset_token":  "valid_token",
						"password_reset_expiry": expiry,
					},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				validator.On("ValidatePassword", mock.Anything, testUser, "newpassword").Return(nil)
				passwordUtils.On("HashPassword", mock.Anything, "newpassword").Return("new_hash", nil)
				store.On("Update", mock.Anything, mock.Anything).Return(nil)
			},
		},
		{
			name:        "invalid token",
			userID:      "user123",
			token:       "invalid_token",
			newPassword: "newpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				expiry := time.Now().Add(1 * time.Hour).Unix()
				testUser := &user.User{
					ID: "user123",
					Metadata: map[string]interface{}{
						"password_reset_token":  "valid_token",
						"password_reset_expiry": expiry,
					},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
			},
			expectedError: "Invalid token",
		},
		{
			name:        "expired token",
			userID:      "user123",
			token:       "valid_token",
			newPassword: "newpassword",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils, validator *mockValidator) {
				expiry := time.Now().Add(-1 * time.Hour).Unix() // Expired
				testUser := &user.User{
					ID: "user123",
					Metadata: map[string]interface{}{
						"password_reset_token":  "valid_token",
						"password_reset_expiry": expiry,
					},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
			},
			expectedError: "Invalid token",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			validator := &mockValidator{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			if tt.useValidator {
				manager.AddValidator(validator)
			}
			
			if tt.setupMocks != nil {
				tt.setupMocks(store, passwordUtils, validator)
			}
			
			ctx := context.Background()
			err := manager.ResetPassword(ctx, tt.userID, tt.token, tt.newPassword)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
			passwordUtils.AssertExpectations(t)
			if tt.useValidator {
				validator.AssertExpectations(t)
			}
		})
	}
}

func TestManager_InitiatePasswordReset(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		setupMocks    func(*mockStore, *mockPasswordUtils)
		expectedError string
	}{
		{
			name:  "successful password reset initiation",
			email: "test@example.com",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:       "user123",
					Email:    "test@example.com",
					Metadata: make(map[string]interface{}),
				}
				store.On("GetByEmail", mock.Anything, "test@example.com").Return(testUser, nil)
				passwordUtils.On("GenerateResetToken", mock.Anything).Return("reset_token", nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					token, hasToken := u.Metadata["password_reset_token"].(string)
					expiry, hasExpiry := u.Metadata["password_reset_expiry"].(int64)
					return u.ID == "user123" && 
						hasToken && token == "reset_token" &&
						hasExpiry && expiry > time.Now().Unix() &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:  "user not found (silent failure)",
			email: "nonexistent@example.com",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				store.On("GetByEmail", mock.Anything, "nonexistent@example.com").Return(nil, errors.New("user not found"))
			},
			// No error expected - prevents email enumeration
		},
		{
			name:  "token generation fails",
			email: "test@example.com",
			setupMocks: func(store *mockStore, passwordUtils *mockPasswordUtils) {
				testUser := &user.User{
					ID:    "user123",
					Email: "test@example.com",
				}
				store.On("GetByEmail", mock.Anything, "test@example.com").Return(testUser, nil)
				passwordUtils.On("GenerateResetToken", mock.Anything).Return("", errors.New("token generation failed"))
			},
			expectedError: "token generation failed",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			
			if tt.setupMocks != nil {
				tt.setupMocks(store, passwordUtils)
			}
			
			ctx := context.Background()
			err := manager.InitiatePasswordReset(ctx, tt.email)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
			passwordUtils.AssertExpectations(t)
		})
	}
}

func TestManager_LockUser(t *testing.T) {
	store := &mockStore{}
	passwordUtils := &mockPasswordUtils{}
	profileStore := &mockProfileStore{}
	
	manager := user.NewManager(store, passwordUtils, profileStore)
	
	testUser := &user.User{
		ID:     "user123",
		Locked: false,
	}
	
	store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
	store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
		return u.ID == "user123" && 
			u.Locked == true &&
			!u.LockoutTime.IsZero() &&
			u.LockoutReason == "Security violation" &&
			!u.UpdatedAt.IsZero()
	})).Return(nil)
	
	ctx := context.Background()
	err := manager.LockUser(ctx, "user123", "Security violation")
	
	assert.NoError(t, err)
	store.AssertExpectations(t)
}

func TestManager_UnlockUser(t *testing.T) {
	store := &mockStore{}
	passwordUtils := &mockPasswordUtils{}
	profileStore := &mockProfileStore{}
	
	manager := user.NewManager(store, passwordUtils, profileStore)
	
	testUser := &user.User{
		ID:                  "user123",
		Locked:              true,
		LockoutTime:         time.Now(),
		LockoutReason:       "Too many failed attempts",
		FailedLoginAttempts: 5,
	}
	
	store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
	store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
		return u.ID == "user123" && 
			u.Locked == false &&
			u.LockoutTime.IsZero() &&
			u.LockoutReason == "" &&
			u.FailedLoginAttempts == 0 &&
			!u.UpdatedAt.IsZero()
	})).Return(nil)
	
	ctx := context.Background()
	err := manager.UnlockUser(ctx, "user123")
	
	assert.NoError(t, err)
	store.AssertExpectations(t)
}

func TestManager_VerifyEmail(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		token         string
		setupMocks    func(*mockStore)
		expectedError string
	}{
		{
			name:   "successful email verification",
			userID: "user123",
			token:  "valid_token",
			setupMocks: func(store *mockStore) {
				expiry := time.Now().Add(1 * time.Hour).Unix()
				testUser := &user.User{
					ID:            "user123",
					EmailVerified: false,
					Metadata: map[string]interface{}{
						"email_verification_token":  "valid_token",
						"email_verification_expiry": expiry,
					},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					_, hasToken := u.Metadata["email_verification_token"]
					_, hasExpiry := u.Metadata["email_verification_expiry"]
					return u.ID == "user123" && 
						u.EmailVerified == true &&
						!hasToken && !hasExpiry &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:   "invalid token",
			userID: "user123",
			token:  "invalid_token",
			setupMocks: func(store *mockStore) {
				expiry := time.Now().Add(1 * time.Hour).Unix()
				testUser := &user.User{
					ID: "user123",
					Metadata: map[string]interface{}{
						"email_verification_token":  "valid_token",
						"email_verification_expiry": expiry,
					},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
			},
			expectedError: "Invalid token",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			
			if tt.setupMocks != nil {
				tt.setupMocks(store)
			}
			
			ctx := context.Background()
			err := manager.VerifyEmail(ctx, tt.userID, tt.token)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
		})
	}
}

func TestManager_SendVerificationEmail(t *testing.T) {
	store := &mockStore{}
	passwordUtils := &mockPasswordUtils{}
	profileStore := &mockProfileStore{}
	
	manager := user.NewManager(store, passwordUtils, profileStore)
	
	testUser := &user.User{
		ID:       "user123",
		Email:    "test@example.com",
		Metadata: make(map[string]interface{}),
	}
	
	store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
	passwordUtils.On("GenerateVerificationToken", mock.Anything).Return("verification_token", nil)
	store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
		token, hasToken := u.Metadata["email_verification_token"].(string)
		expiry, hasExpiry := u.Metadata["email_verification_expiry"].(int64)
		return u.ID == "user123" && 
			hasToken && token == "verification_token" &&
			hasExpiry && expiry > time.Now().Unix() &&
			!u.UpdatedAt.IsZero()
	})).Return(nil)
	
	ctx := context.Background()
	err := manager.SendVerificationEmail(ctx, "user123")
	
	assert.NoError(t, err)
	store.AssertExpectations(t)
	passwordUtils.AssertExpectations(t)
}

func TestManager_EnableMFA(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		method        string
		setupMocks    func(*mockStore)
		expectedError string
	}{
		{
			name:   "successful MFA enablement",
			userID: "user123",
			method: "totp",
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:         "user123",
					MFAEnabled: false,
					MFAMethods: []string{},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.MFAEnabled == true &&
						len(u.MFAMethods) == 1 &&
						u.MFAMethods[0] == "totp" &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:   "MFA method already enabled",
			userID: "user123",
			method: "totp",
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:         "user123",
					MFAEnabled: true,
					MFAMethods: []string{"totp"},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
			},
			expectedError: "Multi-factor authentication already enabled",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			
			if tt.setupMocks != nil {
				tt.setupMocks(store)
			}
			
			ctx := context.Background()
			err := manager.EnableMFA(ctx, tt.userID, tt.method)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
		})
	}
}

func TestManager_DisableMFA(t *testing.T) {
	tests := []struct {
		name          string
		userID        string
		method        string
		setupMocks    func(*mockStore)
		expectedError string
	}{
		{
			name:   "successful MFA disablement - multiple methods",
			userID: "user123",
			method: "totp",
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:         "user123",
					MFAEnabled: true,
					MFAMethods: []string{"totp", "backup_codes"},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.MFAEnabled == true && // Still enabled because backup_codes remain
						len(u.MFAMethods) == 1 &&
						u.MFAMethods[0] == "backup_codes" &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:   "successful MFA disablement - last method",
			userID: "user123",
			method: "totp",
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:         "user123",
					MFAEnabled: true,
					MFAMethods: []string{"totp"},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.MFAEnabled == false && // Disabled because no methods remain
						len(u.MFAMethods) == 0 &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:   "MFA method not enabled",
			userID: "user123",
			method: "webauthn",
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:         "user123",
					MFAEnabled: true,
					MFAMethods: []string{"totp"},
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
			},
			expectedError: "Multi-factor authentication not enabled",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			
			if tt.setupMocks != nil {
				tt.setupMocks(store)
			}
			
			ctx := context.Background()
			err := manager.DisableMFA(ctx, tt.userID, tt.method)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			
			store.AssertExpectations(t)
		})
	}
}

func TestManager_TrackLoginAttempt(t *testing.T) {
	tests := []struct {
		name       string
		userID     string
		successful bool
		setupMocks func(*mockStore)
	}{
		{
			name:       "successful login",
			userID:     "user123",
			successful: true,
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:                  "user123",
					FailedLoginAttempts: 3,
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 0 &&
						!u.LastLogin.IsZero() &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:       "failed login - no lockout",
			userID:     "user123",
			successful: false,
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:                  "user123",
					FailedLoginAttempts: 2,
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 3 &&
						!u.LastFailedLogin.IsZero() &&
						!u.Locked &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
		{
			name:       "failed login - with lockout",
			userID:     "user123",
			successful: false,
			setupMocks: func(store *mockStore) {
				testUser := &user.User{
					ID:                  "user123",
					FailedLoginAttempts: 4, // Next attempt will lock
				}
				store.On("GetByID", mock.Anything, "user123").Return(testUser, nil)
				store.On("Update", mock.Anything, mock.MatchedBy(func(u *user.User) bool {
					return u.ID == "user123" && 
						u.FailedLoginAttempts == 5 &&
						!u.LastFailedLogin.IsZero() &&
						u.Locked == true &&
						!u.LockoutTime.IsZero() &&
						u.LockoutReason == "Too many failed login attempts" &&
						!u.UpdatedAt.IsZero()
				})).Return(nil)
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			passwordUtils := &mockPasswordUtils{}
			profileStore := &mockProfileStore{}
			
			manager := user.NewManager(store, passwordUtils, profileStore)
			
			if tt.setupMocks != nil {
				tt.setupMocks(store)
			}
			
			ctx := context.Background()
			err := manager.TrackLoginAttempt(ctx, tt.userID, tt.successful)
			
			assert.NoError(t, err)
			store.AssertExpectations(t)
		})
	}
}

func TestUserError(t *testing.T) {
	t.Run("Error without cause", func(t *testing.T) {
		err := &user.UserError{
			Code:    "test_error",
			Message: "Test error message",
		}
		
		assert.Equal(t, "Test error message", err.Error())
		assert.Nil(t, err.Unwrap())
	})
	
	t.Run("Error with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &user.UserError{
			Code:    "test_error",
			Message: "Test error message",
			Cause:   cause,
		}
		
		assert.Equal(t, "Test error message: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})
	
	t.Run("WithCause", func(t *testing.T) {
		err := &user.UserError{
			Code:    "test_error",
			Message: "Test error message",
		}
		
		cause := errors.New("new cause")
		errWithCause := err.WithCause(cause)
		
		assert.Equal(t, "test_error", errWithCause.Code)
		assert.Equal(t, "Test error message", errWithCause.Message)
		assert.Equal(t, cause, errWithCause.Cause)
		assert.NotSame(t, err, errWithCause) // Should return a new instance
	})
}