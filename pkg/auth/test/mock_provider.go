package test

import (
	"context"
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// MockAuthProvider implements the AuthProvider interface for testing
type MockAuthProvider struct {
	*providers.BaseAuthProvider
	
	// AuthenticateFunc can be set to mock the Authenticate method
	AuthenticateFunc func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error)
	
	// SupportsFunc can be set to mock the Supports method
	SupportsFunc func(credentials interface{}) bool
	
	// InitializeFunc can be set to mock the Initialize method
	InitializeFunc func(ctx context.Context, config interface{}) error
	
	// ValidateFunc can be set to mock the Validate method
	ValidateFunc func(ctx context.Context) error
	
	// AuthenticateCalls tracks calls to Authenticate
	AuthenticateCalls []struct {
		Ctx         *providers.AuthContext
		Credentials interface{}
	}
	
	// SupportsCalls tracks calls to Supports
	SupportsCalls []struct {
		Credentials interface{}
	}
	
	// InitializeCalls tracks calls to Initialize
	InitializeCalls []struct {
		Ctx    context.Context
		Config interface{}
	}
	
	// ValidateCalls tracks calls to Validate
	ValidateCalls []struct {
		Ctx context.Context
	}
}

// NewMockAuthProvider creates a new mock auth provider with the given metadata
func NewMockAuthProvider(meta metadata.ProviderMetadata) *MockAuthProvider {
	return &MockAuthProvider{
		BaseAuthProvider: providers.NewBaseAuthProvider(meta),
		AuthenticateCalls: make([]struct {
			Ctx         *providers.AuthContext
			Credentials interface{}
		}, 0),
		SupportsCalls: make([]struct {
			Credentials interface{}
		}, 0),
		InitializeCalls: make([]struct {
			Ctx    context.Context
			Config interface{}
		}, 0),
		ValidateCalls: make([]struct {
			Ctx context.Context
		}, 0),
	}
}

// Authenticate mocks the AuthProvider Authenticate method
func (m *MockAuthProvider) Authenticate(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
	m.AuthenticateCalls = append(m.AuthenticateCalls, struct {
		Ctx         *providers.AuthContext
		Credentials interface{}
	}{
		Ctx:         ctx,
		Credentials: credentials,
	})
	
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(ctx, credentials)
	}
	
	// Default mock implementation
	return &providers.AuthResult{
		Success:    false,
		ProviderID: m.GetMetadata().ID,
		Error:      errors.ErrNotImplemented,
	}, errors.ErrNotImplemented
}

// Supports mocks the AuthProvider Supports method
func (m *MockAuthProvider) Supports(credentials interface{}) bool {
	m.SupportsCalls = append(m.SupportsCalls, struct {
		Credentials interface{}
	}{
		Credentials: credentials,
	})
	
	if m.SupportsFunc != nil {
		return m.SupportsFunc(credentials)
	}
	
	// Default mock implementation: support all credentials
	return true
}

// Initialize mocks the Provider Initialize method
func (m *MockAuthProvider) Initialize(ctx context.Context, config interface{}) error {
	m.InitializeCalls = append(m.InitializeCalls, struct {
		Ctx    context.Context
		Config interface{}
	}{
		Ctx:    ctx,
		Config: config,
	})
	
	if m.InitializeFunc != nil {
		return m.InitializeFunc(ctx, config)
	}
	
	// Default mock implementation
	return nil
}

// Validate mocks the Provider Validate method
func (m *MockAuthProvider) Validate(ctx context.Context) error {
	m.ValidateCalls = append(m.ValidateCalls, struct {
		Ctx context.Context
	}{
		Ctx: ctx,
	})
	
	if m.ValidateFunc != nil {
		return m.ValidateFunc(ctx)
	}
	
	// Default mock implementation
	return nil
}