package webauthn_test

import (
	"context"
	"testing"
	"time"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers/webauthn"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock StateStore implementation
type mockStateStore struct {
	mock.Mock
}

func (m *mockStateStore) StoreState(ctx context.Context, namespace string, entityID string, key string, value interface{}) error {
	args := m.Called(ctx, namespace, entityID, key, value)
	return args.Error(0)
}

func (m *mockStateStore) GetState(ctx context.Context, namespace string, entityID string, key string, valuePtr interface{}) error {
	args := m.Called(ctx, namespace, entityID, key, valuePtr)
	return args.Error(0)
}

func (m *mockStateStore) DeleteState(ctx context.Context, namespace string, entityID string, key string) error {
	args := m.Called(ctx, namespace, entityID, key)
	return args.Error(0)
}

func (m *mockStateStore) ListStateKeys(ctx context.Context, namespace string, entityID string) ([]string, error) {
	args := m.Called(ctx, namespace, entityID)
	return args.Get(0).([]string), args.Error(1)
}

func TestProvider_New(t *testing.T) {
	tests := []struct {
		name          string
		config        *webauthn.Config
		expectedError string
	}{
		{
			name: "valid config",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				RPOrigins:     []string{"http://localhost"},
				StateStore:    &mockStateStore{},
			},
			expectedError: "",
		},
		{
			name: "missing rp_display_name",
			config: &webauthn.Config{
				RPID:       "localhost",
				RPOrigins:  []string{"http://localhost"},
				StateStore: &mockStateStore{},
			},
			expectedError: "rp_display_name is required",
		},
		{
			name: "missing rp_id",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPOrigins:     []string{"http://localhost"},
				StateStore:    &mockStateStore{},
			},
			expectedError: "rp_id is required",
		},
		{
			name: "missing rp_origins",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				StateStore:    &mockStateStore{},
			},
			expectedError: "at least one rp_origin is required",
		},
		{
			name: "missing state_store",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				RPOrigins:     []string{"http://localhost"},
			},
			expectedError: "state_store is required",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := webauthn.New(tt.config)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestProvider_Initialize(t *testing.T) {
	mockStore := &mockStateStore{}
	
	tests := []struct {
		name          string
		config        interface{}
		expectedError string
	}{
		{
			name: "valid config",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "localhost",
				RPOrigins:     []string{"http://localhost"},
				StateStore:    mockStore,
			},
			expectedError: "",
		},
		{
			name:          "invalid config type",
			config:        "invalid",
			expectedError: "expected *Config",
		},
		{
			name:          "nil config",
			config:        nil,
			expectedError: "expected *Config",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := webauthn.New(&webauthn.Config{
				RPDisplayName: "Initial",
				RPID:          "initial",
				RPOrigins:     []string{"http://initial"},
				StateStore:    mockStore,
			})
			require.NoError(t, err)
			
			err = provider.Initialize(context.Background(), tt.config)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_Supports(t *testing.T) {
	mockStore := &mockStateStore{}
	provider, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		StateStore:    mockStore,
	})
	require.NoError(t, err)
	
	tests := []struct {
		name        string
		credentials interface{}
		expected    bool
	}{
		{
			name: "WebAuthnAuthenticationCredentials pointer",
			credentials: &webauthn.WebAuthnAuthenticationCredentials{
				CredentialID: "test",
				Response:     []byte("response"),
			},
			expected: true,
		},
		{
			name: "WebAuthnAuthenticationCredentials value",
			credentials: webauthn.WebAuthnAuthenticationCredentials{
				CredentialID: "test",
				Response:     []byte("response"),
			},
			expected: true,
		},
		{
			name: "map with webauthn fields",
			credentials: map[string]interface{}{
				"credentialId": "test",
				"response":     []byte("response"),
			},
			expected: true,
		},
		{
			name: "map without webauthn fields",
			credentials: map[string]interface{}{
				"username": "test",
				"password": "password",
			},
			expected: false,
		},
		{
			name:        "unsupported type",
			credentials: "invalid",
			expected:    false,
		},
		{
			name:        "nil credentials",
			credentials: nil,
			expected:    false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := provider.Supports(tt.credentials)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProvider_Setup(t *testing.T) {
	mockStore := &mockStateStore{}
	provider, err := webauthn.New(&webauthn.Config{
		RPDisplayName:    "Test App",
		RPID:             "localhost",
		RPOrigins:        []string{"http://localhost"},
		StateStore:       mockStore,
		Timeout:          60 * time.Second,
		ChallengeTimeout: 5 * time.Minute,
	})
	require.NoError(t, err)
	
	ctx := context.Background()
	userID := "test-user"
	
	// Setup mock expectations
	mockStore.On("StoreState", ctx, "webauthn_challenges", userID, mock.AnythingOfType("string"), mock.AnythingOfType("*webauthn.Challenge")).Return(nil)
	mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Return(nil)
	
	// Call Setup
	setupData, err := provider.Setup(ctx, userID)
	
	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, "webauthn", setupData.ProviderID)
	assert.Equal(t, userID, setupData.UserID)
	assert.NotEmpty(t, setupData.Secret) // Challenge ID
	assert.NotEmpty(t, setupData.QRCode) // Options JSON
	
	// Verify additional data
	assert.Contains(t, setupData.AdditionalData, "challenge_id")
	assert.Contains(t, setupData.AdditionalData, "rp_id")
	assert.Contains(t, setupData.AdditionalData, "timeout")
	assert.Equal(t, "localhost", setupData.AdditionalData["rp_id"])
	assert.Equal(t, float64(60), setupData.AdditionalData["timeout"])
	
	mockStore.AssertExpectations(t)
}

func TestProvider_GenerateBackupCodes(t *testing.T) {
	mockStore := &mockStateStore{}
	provider, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		StateStore:    mockStore,
	})
	require.NoError(t, err)
	
	ctx := context.Background()
	userID := "test-user"
	
	// GenerateBackupCodes should not be supported for WebAuthn
	codes, err := provider.GenerateBackupCodes(ctx, userID, 10)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backup codes are not supported for WebAuthn")
	assert.Nil(t, codes)
}

func TestProvider_BeginRegistration(t *testing.T) {
	mockStore := &mockStateStore{}
	provider, err := webauthn.New(&webauthn.Config{
		RPDisplayName:       "Test App",
		RPID:                "localhost",
		RPOrigins:           []string{"http://localhost"},
		StateStore:          mockStore,
		Timeout:             60 * time.Second,
		ChallengeTimeout:    5 * time.Minute,
		SupportedAlgorithms: []int64{-7, -257},
	})
	require.NoError(t, err)
	
	ctx := context.Background()
	userID := "test-user"
	username := "testuser"
	displayName := "Test User"
	
	// Setup mock expectations
	mockStore.On("StoreState", ctx, "webauthn_challenges", userID, mock.AnythingOfType("string"), mock.AnythingOfType("*webauthn.Challenge")).Return(nil)
	mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Return(nil)
	
	// Call BeginRegistration
	options, err := provider.BeginRegistration(ctx, userID, username, displayName)
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, options)
	assert.NotEmpty(t, options.Challenge)
	assert.Equal(t, "localhost", options.RelyingParty.ID)
	assert.Equal(t, "Test App", options.RelyingParty.Name)
	assert.Equal(t, username, options.User.Name)
	assert.Equal(t, displayName, options.User.DisplayName)
	assert.Len(t, options.PubKeyCredParams, 2)
	assert.Equal(t, int64(-7), options.PubKeyCredParams[0].Algorithm)
	assert.Equal(t, int64(-257), options.PubKeyCredParams[1].Algorithm)
	
	mockStore.AssertExpectations(t)
}

func TestProvider_BeginAuthentication(t *testing.T) {
	mockStore := &mockStateStore{}
	provider, err := webauthn.New(&webauthn.Config{
		RPDisplayName:    "Test App",
		RPID:             "localhost",
		RPOrigins:        []string{"http://localhost"},
		StateStore:       mockStore,
		Timeout:          60 * time.Second,
		ChallengeTimeout: 5 * time.Minute,
		UserVerification: webauthn.UserVerificationPreferred,
	})
	require.NoError(t, err)
	
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("user with credentials", func(t *testing.T) {
		// Setup test data
		testCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
					Transport: []string{"usb", "nfc"},
				},
				{
					ID:        []byte("cred2"),
					PublicKey: []byte("pubkey2"),
					Transport: []string{"internal"},
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *testCreds
		}).Return(nil).Once()
		
		mockStore.On("StoreState", ctx, "webauthn_challenges", userID, mock.AnythingOfType("string"), mock.AnythingOfType("*webauthn.Challenge")).Return(nil).Once()
		
		// Call BeginAuthentication
		options, err := provider.BeginAuthentication(ctx, userID)
		
		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, options)
		assert.NotEmpty(t, options.Challenge)
		assert.Equal(t, "localhost", options.RelyingPartyID)
		assert.Equal(t, webauthn.UserVerificationPreferred, options.UserVerification)
		assert.Len(t, options.AllowCredentials, 2)
		
		// Verify allowed credentials
		assert.Equal(t, "public-key", options.AllowCredentials[0].Type)
		assert.Equal(t, []byte("cred1"), options.AllowCredentials[0].ID)
		assert.Equal(t, []string{"usb", "nfc"}, options.AllowCredentials[0].Transports)
		
		assert.Equal(t, "public-key", options.AllowCredentials[1].Type)
		assert.Equal(t, []byte("cred2"), options.AllowCredentials[1].ID)
		assert.Equal(t, []string{"internal"}, options.AllowCredentials[1].Transports)
		
		mockStore.AssertExpectations(t)
	})
	
	t.Run("user without credentials", func(t *testing.T) {
		// Setup mock expectations - return empty credentials
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Return(nil).Once()
		
		// Call BeginAuthentication
		options, err := provider.BeginAuthentication(ctx, userID)
		
		// Should fail with user not found
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrUserNotFound, err)
		assert.Nil(t, options)
		
		mockStore.AssertExpectations(t)
	})
}

func TestProvider_GetMetadata(t *testing.T) {
	mockStore := &mockStateStore{}
	provider, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Test App",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
		StateStore:    mockStore,
	})
	require.NoError(t, err)
	
	meta := provider.GetMetadata()
	
	assert.Equal(t, "webauthn", meta.ID)
	assert.Equal(t, metadata.ProviderTypeAuth, meta.Type)
	assert.Equal(t, "WebAuthn", meta.Name)
	assert.Contains(t, meta.Description, "WebAuthn/FIDO2")
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, "auth2", meta.Author)
}