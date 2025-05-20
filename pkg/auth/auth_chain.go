package auth

import (
	"context"
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/google/uuid"
)

// AuthHandlerFunc defines a function that processes an authentication request
type AuthHandlerFunc func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error)

// AuthChain implements a chain of responsibility for authentication
type AuthChain struct {
	manager     *Manager
	handlers    []AuthHandlerFunc
	middlewares []AuthHandlerFunc
}

// NewAuthChain creates a new authentication chain using the provided manager
func NewAuthChain(manager *Manager) *AuthChain {
	return &AuthChain{
		manager:     manager,
		handlers:    make([]AuthHandlerFunc, 0),
		middlewares: make([]AuthHandlerFunc, 0),
	}
}

// Use adds a middleware to the authentication chain
// Middlewares are executed in the order they are added before any handlers
func (c *AuthChain) Use(middleware AuthHandlerFunc) *AuthChain {
	c.middlewares = append(c.middlewares, middleware)
	return c
}

// Handler adds a handler to the authentication chain
// Handlers are executed in the order they are added
func (c *AuthChain) Handler(handler AuthHandlerFunc) *AuthChain {
	c.handlers = append(c.handlers, handler)
	return c
}

// DefaultProviderHandler returns a handler that uses the default provider
func (c *AuthChain) DefaultProviderHandler() AuthHandlerFunc {
	return func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
		// Skip if no default provider is configured
		if c.manager.Config.DefaultProviderID == "" {
			return next(ctx, credentials, next)
		}
		
		provider, err := c.manager.GetProvider(c.manager.Config.DefaultProviderID)
		if err != nil {
			// Skip to the next handler if provider not found
			return next(ctx, credentials, next)
		}
		
		if !provider.Supports(credentials) {
			// Skip to the next handler if provider doesn't support these credentials
			return next(ctx, credentials, next)
		}
		
		// Try to authenticate with this provider
		result, err := provider.Authenticate(ctx, credentials)
		if err != nil || !result.Success {
			// Continue to next handler on failure
			return next(ctx, credentials, next)
		}
		
		return result, nil
	}
}

// AllProvidersHandler returns a handler that tries all providers
func (c *AuthChain) AllProvidersHandler() AuthHandlerFunc {
	return func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
		providersList := c.manager.GetProviders()
		
		// Find all providers that support this credential type
		var supportingProviders []providers.AuthProvider
		for _, provider := range providersList {
			if provider.Supports(credentials) {
				supportingProviders = append(supportingProviders, provider)
			}
		}
		
		if len(supportingProviders) == 0 {
			// No providers support these credentials, continue to next handler
			return next(ctx, credentials, next)
		}
		
		// Try each provider until one succeeds or all fail
		var combinedResult *providers.AuthResult
		
		for _, provider := range supportingProviders {
			result, err := provider.Authenticate(ctx, credentials)
			
			// Return immediately on success
			if err == nil && result.Success {
				return result, nil
			}
			
			// Combine results (for MFA requirements, etc.)
			if combinedResult == nil {
				combinedResult = result
			} else if result != nil {
				// Collect MFA providers across results
				if result.RequiresMFA && len(result.MFAProviders) > 0 {
					if combinedResult.MFAProviders == nil {
						combinedResult.MFAProviders = make([]string, 0)
					}
					combinedResult.MFAProviders = append(combinedResult.MFAProviders, result.MFAProviders...)
				}
				
				// Collect extra data
				if result.Extra != nil {
					if combinedResult.Extra == nil {
						combinedResult.Extra = make(map[string]interface{})
					}
					for k, v := range result.Extra {
						combinedResult.Extra[k] = v
					}
				}
			}
		}
		
		// If all providers failed, try the next handler
		if combinedResult == nil || !combinedResult.Success {
			return next(ctx, credentials, next)
		}
		
		return combinedResult, nil
	}
}

// SpecificProviderHandler returns a handler that uses a specific provider
func (c *AuthChain) SpecificProviderHandler(providerID string) AuthHandlerFunc {
	return func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
		provider, err := c.manager.GetProvider(providerID)
		if err != nil {
			// Skip to the next handler if provider not found
			return next(ctx, credentials, next)
		}
		
		if !provider.Supports(credentials) {
			// Skip to the next handler if provider doesn't support these credentials
			return next(ctx, credentials, next)
		}
		
		// Try to authenticate with this provider
		result, err := provider.Authenticate(ctx, credentials)
		if err != nil || !result.Success {
			// Continue to next handler on failure
			return next(ctx, credentials, next)
		}
		
		return result, nil
	}
}

// endOfChain is the terminating handler that returns a standard error
func endOfChain(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
	return &providers.AuthResult{
		Success: false,
		Error:   providers.NewAuthFailedError("no handler succeeded", nil),
	}, providers.NewAuthFailedError("no handler succeeded", nil)
}

// Authenticate authenticates a user using the chain of responsibility
func (c *AuthChain) Authenticate(ctx context.Context, credentials providers.Credentials) (*providers.AuthResult, error) {
	// Create authentication context with request ID
	authCtx := &providers.AuthContext{
		OriginalContext: ctx,
		RequestID:       uuid.New().String(),
		RequestMetadata: make(map[string]interface{}),
	}
	
	// Extract client information from context if available
	if clientIP, ok := ctx.Value("client_ip").(string); ok {
		authCtx.ClientIP = clientIP
	}
	
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		authCtx.UserAgent = userAgent
	}
	
	// Check if we have any handlers
	if len(c.handlers) == 0 {
		return nil, errors.WrapError(
			errors.ErrServiceUnavailable,
			errors.CodeUnavailable,
			"no authentication handlers configured",
		)
	}
	
	// Combine middlewares and handlers
	chain := make([]AuthHandlerFunc, 0, len(c.middlewares)+len(c.handlers))
	chain = append(chain, c.middlewares...)
	chain = append(chain, c.handlers...)
	
	// Build the chain of handlers
	var next AuthHandlerFunc = endOfChain
	for i := len(chain) - 1; i >= 0; i-- {
		currentHandler := chain[i]
		previousNext := next
		next = func(currentHandler AuthHandlerFunc, previousNext AuthHandlerFunc) AuthHandlerFunc {
			return func(ctx *providers.AuthContext, credentials providers.Credentials, _ AuthHandlerFunc) (*providers.AuthResult, error) {
				return currentHandler(ctx, credentials, previousNext)
			}
		}(currentHandler, previousNext)
	}
	
	// Start the chain
	return next(authCtx, credentials, nil)
}

// BuildDefaultChain returns a chain with default handlers
func (c *AuthChain) BuildDefaultChain() *AuthChain {
	return c.Handler(c.DefaultProviderHandler()).Handler(c.AllProvidersHandler())
}

// RateLimitingMiddleware creates a middleware that implements rate limiting
func RateLimitingMiddleware(maxAttempts int, lockoutDuration int64) AuthHandlerFunc {
	// In a real implementation, this would use a proper rate limiter
	return func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
		// Implement rate limiting logic here
		// For now, just pass through
		return next(ctx, credentials, next)
	}
}

// LoggingMiddleware creates a middleware that logs authentication attempts
func LoggingMiddleware() AuthHandlerFunc {
	return func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
		// Log the authentication attempt
		// In a real implementation, this would use a proper logger
		
		// Call the next handler
		result, err := next(ctx, credentials, next)
		
		// Log the result
		// In a real implementation, this would use a proper logger
		
		return result, err
	}
}

// AuditingMiddleware creates a middleware that records audit events
func AuditingMiddleware() AuthHandlerFunc {
	return func(ctx *providers.AuthContext, credentials providers.Credentials, next AuthHandlerFunc) (*providers.AuthResult, error) {
		// Record the authentication attempt for auditing
		
		// Call the next handler
		result, err := next(ctx, credentials, next)
		
		// Record the result for auditing
		
		return result, err
	}
}