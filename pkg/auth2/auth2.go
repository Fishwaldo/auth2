package auth2

import (
	"context"
	"fmt"
	"sync"

	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/config"
	"github.com/Fishwaldo/auth2/pkg/log"
)

// Auth2 is the main entry point for the auth2 library
type Auth2 struct {
	// Configuration
	config *config.Config
	
	// Logger
	logger *log.Logger
	
	// Registered plugins and providers
	providers  map[string]interface{}
	
	// Mutex for concurrent access
	mu sync.RWMutex
}

// New creates a new Auth2 instance with the provided configuration
func New(cfg *config.Config) (*Auth2, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	
	// Configure logging
	logger := cfg.ConfigureLogging()
	
	a := &Auth2{
		config:    cfg,
		logger:    logger,
		providers: make(map[string]interface{}),
	}
	
	return a, nil
}

// Config returns the current configuration
func (a *Auth2) Config() *config.Config {
	return a.config
}

// Logger returns the logger
func (a *Auth2) Logger() *log.Logger {
	return a.logger
}

// GetProvider returns a registered provider by name and type
func (a *Auth2) GetProvider(name string, providerType interface{}) (interface{}, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	key := providerTypeKey(name, providerType)
	if provider, ok := a.providers[key]; ok {
		return provider, nil
	}
	
	return nil, errors.NewPluginError(
		errors.ErrPluginNotFound,
		getProviderTypeName(providerType),
		name,
		"provider not registered",
	)
}

// RegisterProvider registers a new provider
func (a *Auth2) RegisterProvider(name string, providerType interface{}, provider interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	key := providerTypeKey(name, providerType)
	
	// Check if already registered
	if _, exists := a.providers[key]; exists {
		return errors.NewPluginError(
			errors.ErrInvalidOperation,
			getProviderTypeName(providerType),
			name,
			"provider already registered",
		)
	}
	
	a.providers[key] = provider
	a.logger.Info("Registered provider", "name", name, "type", getProviderTypeName(providerType))
	
	return nil
}

// UnregisterProvider removes a registered provider
func (a *Auth2) UnregisterProvider(name string, providerType interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	key := providerTypeKey(name, providerType)
	
	if _, exists := a.providers[key]; !exists {
		return errors.NewPluginError(
			errors.ErrPluginNotFound,
			getProviderTypeName(providerType),
			name,
			"provider not registered",
		)
	}
	
	delete(a.providers, key)
	a.logger.Info("Unregistered provider", "name", name, "type", getProviderTypeName(providerType))
	
	return nil
}

// providerTypeKey generates a key for the providers map
func providerTypeKey(name string, providerType interface{}) string {
	return name + ":" + getProviderTypeName(providerType)
}

// getProviderTypeName returns a string representation of the provider type
func getProviderTypeName(providerType interface{}) string {
	switch providerType.(type) {
	case nil:
		return "unknown"
	default:
		return fmt.Sprintf("%T", providerType)
	}
}

// Context returns a new context with the auth2 instance
func (a *Auth2) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, auth2Key{}, a)
}

// FromContext retrieves the auth2 instance from the context
func FromContext(ctx context.Context) (*Auth2, bool) {
	if auth, ok := ctx.Value(auth2Key{}).(*Auth2); ok {
		return auth, true
	}
	return nil, false
}

// auth2Key is used as the key for storing the auth2 instance in the context
type auth2Key struct{}

// Initialize sets up the Auth2 instance
func (a *Auth2) Initialize(ctx context.Context) error {
	// Initialize components based on configuration
	a.logger.Info("Initializing auth2", "version", Version)
	
	// Additional initialization logic will be added as components are implemented
	
	return nil
}

// Shutdown performs cleanup operations
func (a *Auth2) Shutdown(ctx context.Context) error {
	a.logger.Info("Shutting down auth2")
	
	// Cleanup logic will be added as components are implemented
	
	return nil
}