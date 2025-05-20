package metadata

import (
	"context"
)

// MFAProvider defines the interface for multi-factor authentication providers
type MFAProvider interface {
	Provider
	
	// Setup initializes the MFA method for a user
	Setup(ctx context.Context, userID string) (SetupData, error)
	
	// Verify checks if the provided code is valid
	Verify(ctx context.Context, userID string, code string) (bool, error)
	
	// GenerateBackupCodes generates backup codes for a user
	// Returns the generated codes or an error
	GenerateBackupCodes(ctx context.Context, userID string, count int) ([]string, error)
}

// SetupData contains data needed for setting up MFA
type SetupData struct {
	// ProviderID is the ID of the MFA provider
	ProviderID string
	
	// UserID is the ID of the user
	UserID string
	
	// Secret is the MFA secret (if applicable)
	Secret string
	
	// QRCode is the QR code for the MFA setup (if applicable)
	QRCode []byte
	
	// VerificationURI is the URI for verification (if applicable)
	VerificationURI string
	
	// AdditionalData contains additional provider-specific data
	AdditionalData map[string]interface{}
}

// DualModeProvider implements both AuthProvider and MFAProvider interfaces
// This is used for methods like WebAuthn that can function as both primary
// authentication and as a second factor
type DualModeProvider interface {
	AuthProvider
	MFAProvider
}

// BaseMFAProvider provides a base implementation of the MFAProvider interface
type BaseMFAProvider struct {
	*BaseProvider
}

// NewBaseMFAProvider creates a new BaseMFAProvider
func NewBaseMFAProvider(metadata ProviderMetadata) *BaseMFAProvider {
	return &BaseMFAProvider{
		BaseProvider: NewBaseProvider(metadata),
	}
}

// Setup provides a default implementation that always fails
func (p *BaseMFAProvider) Setup(ctx context.Context, userID string) (SetupData, error) {
	return SetupData{}, ErrNotImplemented
}

// Verify provides a default implementation that always fails
func (p *BaseMFAProvider) Verify(ctx context.Context, userID string, code string) (bool, error) {
	return false, ErrNotImplemented
}

// GenerateBackupCodes provides a default implementation that always fails
func (p *BaseMFAProvider) GenerateBackupCodes(ctx context.Context, userID string, count int) ([]string, error) {
	return nil, ErrNotImplemented
}