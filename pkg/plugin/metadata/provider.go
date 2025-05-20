package metadata

import (
	"context"
	"fmt"
	"github.com/Fishwaldo/auth2/internal/errors"
)

// ProviderType defines the type of provider
type ProviderType string

const (
	// ProviderTypeAuth represents an authentication provider
	ProviderTypeAuth ProviderType = "auth"
	// ProviderTypeMFA represents a multi-factor authentication provider
	ProviderTypeMFA ProviderType = "mfa"
	// ProviderTypeStorage represents a storage adapter
	ProviderTypeStorage ProviderType = "storage"
	// ProviderTypeHTTP represents an HTTP framework adapter
	ProviderTypeHTTP ProviderType = "http"
	// ProviderTypeEmail represents an email provider
	ProviderTypeEmail ProviderType = "email"
	// ProviderTypeRateLimit represents a rate limiter
	ProviderTypeRateLimit ProviderType = "ratelimit"
	// ProviderTypeCSRF represents a CSRF protector
	ProviderTypeCSRF ProviderType = "csrf"
)

// VersionConstraint defines the version compatibility for a provider
type VersionConstraint struct {
	// MinVersion is the minimum compatible version
	MinVersion string
	// MaxVersion is the maximum compatible version (empty means no upper bound)
	MaxVersion string
}

// ProviderMetadata contains information about a provider
type ProviderMetadata struct {
	// ID is a unique identifier for the provider
	ID string
	// Type is the type of provider
	Type ProviderType
	// Version is the provider version
	Version string
	// Name is a human-readable name for the provider
	Name string
	// Description provides details about the provider
	Description string
	// Author is the provider author
	Author string
	// VersionConstraint defines the compatibility with auth2 versions
	VersionConstraint VersionConstraint
}

// Provider defines the base interface that all providers must implement
type Provider interface {
	// GetMetadata returns provider metadata
	GetMetadata() ProviderMetadata
	
	// Initialize sets up the provider with necessary configuration
	Initialize(ctx context.Context, config interface{}) error
	
	// Validate checks if the provider is properly configured
	Validate(ctx context.Context) error
	
	// IsCompatibleVersion checks if the provider is compatible with a given version
	IsCompatibleVersion(version string) bool
}

// BaseProvider provides a default implementation of the Provider interface
type BaseProvider struct {
	// metadata contains provider information
	metadata ProviderMetadata
}

// NewBaseProvider creates a new BaseProvider with the given metadata
func NewBaseProvider(metadata ProviderMetadata) *BaseProvider {
	return &BaseProvider{
		metadata: metadata,
	}
}

// GetMetadata returns provider metadata
func (p *BaseProvider) GetMetadata() ProviderMetadata {
	return p.metadata
}

// Initialize provides a default implementation that always succeeds
func (p *BaseProvider) Initialize(ctx context.Context, config interface{}) error {
	// Default implementation does nothing
	return nil
}

// Validate provides a default implementation that always succeeds
func (p *BaseProvider) Validate(ctx context.Context) error {
	// Default implementation does nothing
	return nil
}

// IsCompatibleVersion checks if the provider is compatible with a given version
func (p *BaseProvider) IsCompatibleVersion(version string) bool {
	// If no constraint is defined, assume compatibility
	if p.metadata.VersionConstraint.MinVersion == "" && p.metadata.VersionConstraint.MaxVersion == "" {
		return true
	}
	
	// Check minimum version if defined
	if p.metadata.VersionConstraint.MinVersion != "" {
		minOk, err := errors.CompareVersions(version, p.metadata.VersionConstraint.MinVersion)
		if err != nil || minOk < 0 {
			return false
		}
	}
	
	// Check maximum version if defined
	if p.metadata.VersionConstraint.MaxVersion != "" {
		maxOk, err := errors.CompareVersions(version, p.metadata.VersionConstraint.MaxVersion)
		if err != nil || maxOk > 0 {
			return false
		}
	}
	
	return true
}

// String returns a string representation of a ProviderType
func (pt ProviderType) String() string {
	return string(pt)
}

// ValidateMetadata checks if provider metadata is valid
func ValidateMetadata(metadata ProviderMetadata) error {
	if metadata.ID == "" {
		return fmt.Errorf("provider ID cannot be empty")
	}
	
	if metadata.Type == "" {
		return fmt.Errorf("provider type cannot be empty")
	}
	
	if metadata.Version == "" {
		return fmt.Errorf("provider version cannot be empty")
	}
	
	if metadata.Name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}
	
	return nil
}