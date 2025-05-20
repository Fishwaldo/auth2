package metadata_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

func TestValidateMetadataBlackBox(t *testing.T) {
	tests := []struct {
		name     string
		metadata metadata.ProviderMetadata
		wantErr  bool
	}{
		{
			name: "Valid metadata",
			metadata: metadata.ProviderMetadata{
				ID:      "test-provider",
				Type:    metadata.ProviderTypeAuth,
				Version: "1.0.0",
				Name:    "Test Provider",
			},
			wantErr: false,
		},
		{
			name: "Missing ID",
			metadata: metadata.ProviderMetadata{
				Type:    metadata.ProviderTypeAuth,
				Version: "1.0.0",
				Name:    "Test Provider",
			},
			wantErr: true,
		},
		{
			name: "Missing Type",
			metadata: metadata.ProviderMetadata{
				ID:      "test-provider",
				Version: "1.0.0",
				Name:    "Test Provider",
			},
			wantErr: true,
		},
		{
			name: "Missing Version",
			metadata: metadata.ProviderMetadata{
				ID:   "test-provider",
				Type: metadata.ProviderTypeAuth,
				Name: "Test Provider",
			},
			wantErr: true,
		},
		{
			name: "Missing Name",
			metadata: metadata.ProviderMetadata{
				ID:      "test-provider",
				Type:    metadata.ProviderTypeAuth,
				Version: "1.0.0",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := metadata.ValidateMetadata(tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCreateProvider tests the creation and basic functionality of a provider
func TestCreateProvider(t *testing.T) {
	// Create metadata
	meta := metadata.ProviderMetadata{
		ID:      "test-provider",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Test Provider",
		VersionConstraint: metadata.VersionConstraint{
			MinVersion: "1.0.0",
			MaxVersion: "2.0.0",
		},
	}

	// Create provider
	provider := metadata.NewBaseProvider(meta)

	// Test GetMetadata
	providerMeta := provider.GetMetadata()
	if providerMeta.ID != "test-provider" {
		t.Errorf("GetMetadata().ID = %v, want %v", providerMeta.ID, "test-provider")
	}
	if providerMeta.Type != metadata.ProviderTypeAuth {
		t.Errorf("GetMetadata().Type = %v, want %v", providerMeta.Type, metadata.ProviderTypeAuth)
	}
	if providerMeta.Version != "1.0.0" {
		t.Errorf("GetMetadata().Version = %v, want %v", providerMeta.Version, "1.0.0")
	}
	if providerMeta.Name != "Test Provider" {
		t.Errorf("GetMetadata().Name = %v, want %v", providerMeta.Name, "Test Provider")
	}

	// Test Initialize (should not fail with default implementation)
	if err := provider.Initialize(context.Background(), nil); err != nil {
		t.Errorf("Initialize() error = %v, want nil", err)
	}

	// Test Validate (should not fail with default implementation)
	if err := provider.Validate(context.Background()); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

// TestProviderVersionCompatibility tests the version compatibility checking
func TestProviderVersionCompatibility(t *testing.T) {
	testCases := []struct {
		name           string
		minVersion     string
		maxVersion     string
		testVersion    string
		expectCompatible bool
	}{
		{
			name:            "Version in range",
			minVersion:      "1.0.0",
			maxVersion:      "2.0.0",
			testVersion:     "1.5.0",
			expectCompatible: true,
		},
		{
			name:            "Version at minimum",
			minVersion:      "1.0.0",
			maxVersion:      "2.0.0",
			testVersion:     "1.0.0",
			expectCompatible: true,
		},
		{
			name:            "Version at maximum",
			minVersion:      "1.0.0",
			maxVersion:      "2.0.0",
			testVersion:     "2.0.0",
			expectCompatible: true,
		},
		{
			name:            "Version below minimum",
			minVersion:      "1.0.0",
			maxVersion:      "2.0.0",
			testVersion:     "0.9.0",
			expectCompatible: false,
		},
		{
			name:            "Version above maximum",
			minVersion:      "1.0.0",
			maxVersion:      "2.0.0",
			testVersion:     "2.1.0",
			expectCompatible: false,
		},
		{
			name:            "No constraints",
			minVersion:      "",
			maxVersion:      "",
			testVersion:     "3.0.0",
			expectCompatible: true,
		},
		{
			name:            "Only minimum constraint",
			minVersion:      "1.0.0",
			maxVersion:      "",
			testVersion:     "3.0.0",
			expectCompatible: true,
		},
		{
			name:            "Only maximum constraint",
			minVersion:      "",
			maxVersion:      "2.0.0",
			testVersion:     "1.0.0",
			expectCompatible: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			meta := metadata.ProviderMetadata{
				ID:      "test-provider",
				Type:    metadata.ProviderTypeAuth,
				Version: "1.0.0",
				Name:    "Test Provider",
				VersionConstraint: metadata.VersionConstraint{
					MinVersion: tc.minVersion,
					MaxVersion: tc.maxVersion,
				},
			}

			provider := metadata.NewBaseProvider(meta)
			isCompatible := provider.IsCompatibleVersion(tc.testVersion)

			if isCompatible != tc.expectCompatible {
				t.Errorf("IsCompatibleVersion(%s) = %v, want %v", 
					tc.testVersion, isCompatible, tc.expectCompatible)
			}
		})
	}
}

// TestAuthProvider tests the auth provider interface functionality
func TestAuthProvider(t *testing.T) {
	meta := metadata.ProviderMetadata{
		ID:      "test-auth",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Test Auth Provider",
	}

	provider := metadata.NewBaseAuthProvider(meta)

	// Test that the provider properly implements both interfaces
	providerMeta := provider.GetMetadata()
	if providerMeta.ID != "test-auth" {
		t.Errorf("GetMetadata().ID = %v, want %v", providerMeta.ID, "test-auth")
	}

	// Test default implementation of authenticate (should return error)
	_, err := provider.Authenticate(context.Background(), nil)
	if err == nil {
		t.Errorf("Authenticate() should return an error for default implementation")
	}

	// Test supports method (default implementation should return false)
	if provider.Supports(nil) {
		t.Errorf("Supports() should return false for default implementation")
	}
}

// TestMFAProvider tests the MFA provider interface functionality
func TestMFAProvider(t *testing.T) {
	meta := metadata.ProviderMetadata{
		ID:      "test-mfa",
		Type:    metadata.ProviderTypeMFA,
		Version: "1.0.0",
		Name:    "Test MFA Provider",
	}

	provider := metadata.NewBaseMFAProvider(meta)

	// Test that the provider properly implements both interfaces
	providerMeta := provider.GetMetadata()
	if providerMeta.ID != "test-mfa" {
		t.Errorf("GetMetadata().ID = %v, want %v", providerMeta.ID, "test-mfa")
	}

	// Test default implementation of setup (should return error)
	_, err := provider.Setup(context.Background(), "user123")
	if err == nil {
		t.Errorf("Setup() should return an error for default implementation")
	}

	// Test verify method (default implementation should return error)
	_, err = provider.Verify(context.Background(), "user123", "123456")
	if err == nil {
		t.Errorf("Verify() should return an error for default implementation")
	}

	// Test backup codes generation (default implementation should return error)
	_, err = provider.GenerateBackupCodes(context.Background(), "user123", 10)
	if err == nil {
		t.Errorf("GenerateBackupCodes() should return an error for default implementation")
	}
}

// TestAuthProviderCredentials tests the credential types
func TestAuthProviderCredentials(t *testing.T) {
	usernamePasswordCreds := metadata.UsernamePasswordCredentials{
		Username: "testuser",
		Password: "testpass",
	}
	
	oauthCreds := metadata.OAuthCredentials{
		Provider:    "google",
		Code:        "oauth-code",
		RedirectURI: "https://example.com/callback",
		State:       "csrf-token",
	}
	
	samlCreds := metadata.SAMLCredentials{
		SAMLResponse: "saml-response-data",
		RelayState:   "relay-state",
	}
	
	webauthnCreds := metadata.WebAuthnCredentials{
		CredentialID:      []byte("credential-id"),
		AuthenticatorData: []byte("authenticator-data"),
		ClientDataJSON:    []byte("client-data-json"),
		Signature:         []byte("signature"),
		UserHandle:        []byte("user-handle"),
	}
	
	testCases := []struct {
		name  string
		creds metadata.AuthProviderCredentials
		want  string
	}{
		{
			name:  "Username Password Credentials",
			creds: usernamePasswordCreds,
			want:  "username_password",
		},
		{
			name:  "OAuth Credentials",
			creds: oauthCreds,
			want:  "oauth",
		},
		{
			name:  "SAML Credentials",
			creds: samlCreds,
			want:  "saml",
		},
		{
			name:  "WebAuthn Credentials",
			creds: webauthnCreds,
			want:  "webauthn",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.creds.GetType()
			if got != tc.want {
				t.Errorf("GetType() = %v, want %v", got, tc.want)
			}
		})
	}
}