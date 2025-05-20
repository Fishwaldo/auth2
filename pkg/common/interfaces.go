package common

import (
	"context"
)

// Initializable defines an interface for types that need initialization
type Initializable interface {
	// Initialize initializes the component with configuration
	Initialize(ctx context.Context, config interface{}) error
}

// Validator defines an interface for types that can validate
type Validator interface {
	// Validate validates the component's state and configuration
	Validate(ctx context.Context) error
}

// Configurable defines an interface for types that can be configured
type Configurable interface {
	// Configure configures the component with the provided configuration
	Configure(config interface{}) error
	
	// GetConfig returns the component's current configuration
	GetConfig() interface{}
}

// Identifiable defines an interface for types with a unique identifier
type Identifiable interface {
	// GetID returns the unique identifier for the component
	GetID() string
}

// Describable defines an interface for types with descriptive metadata
type Describable interface {
	// GetName returns the human-readable name of the component
	GetName() string
	
	// GetDescription returns a description of the component
	GetDescription() string
	
	// GetVersion returns the version of the component
	GetVersion() string
}

// Lifecycle defines an interface for types with start/stop lifecycle
type Lifecycle interface {
	// Start starts the component
	Start(ctx context.Context) error
	
	// Stop stops the component
	Stop(ctx context.Context) error
	
	// IsRunning returns true if the component is running
	IsRunning() bool
}

// HealthCheck defines an interface for types that can report their health
type HealthCheck interface {
	// HealthCheck performs a health check
	HealthCheck(ctx context.Context) error
	
	// Status returns the current status of the component
	Status(ctx context.Context) (Status, error)
}

// Debuggable defines an interface for types that can provide debug information
type Debuggable interface {
	// GetDebugInfo returns debug information about the component
	GetDebugInfo(ctx context.Context) (map[string]interface{}, error)
}

// Disposable defines an interface for types that need cleanup
type Disposable interface {
	// Dispose cleans up resources used by the component
	Dispose(ctx context.Context) error
}

// Queryable defines a generic interface for querying component capabilities
type Queryable interface {
	// Supports checks if the component supports a specific feature
	Supports(feature string) bool
	
	// GetFeatures returns all supported features
	GetFeatures() []string
}

// Traceable defines an interface for components that can trace operations
type Traceable interface {
	// StartSpan starts a new tracing span
	StartSpan(ctx context.Context, operation string) (context.Context, interface{})
	
	// EndSpan ends a tracing span
	EndSpan(span interface{})
}

// ConfigMap is a generic configuration map
type ConfigMap map[string]interface{}

// LogLevel defines the log level
type LogLevel int

const (
	// LogLevelDebug is the debug log level
	LogLevelDebug LogLevel = iota
	
	// LogLevelInfo is the info log level
	LogLevelInfo
	
	// LogLevelWarn is the warn log level
	LogLevelWarn
	
	// LogLevelError is the error log level
	LogLevelError
	
	// LogLevelFatal is the fatal log level
	LogLevelFatal
)

// StatusCode defines the status of a component
type StatusCode int

const (
	// StatusOK indicates the component is functioning normally
	StatusOK StatusCode = iota
	
	// StatusDegraded indicates the component is functioning with degraded performance
	StatusDegraded
	
	// StatusCritical indicates the component is in a critical state
	StatusCritical
	
	// StatusUnknown indicates the component's status is unknown
	StatusUnknown
)

// Status represents the status of a component
type Status struct {
	// Code is the status code
	Code StatusCode
	
	// Message is a human-readable status message
	Message string
	
	// Details contains additional status details
	Details map[string]interface{}
}

// Identifiers for common features
const (
	// FeatureTracing indicates support for tracing
	FeatureTracing = "tracing"
	
	// FeatureMetrics indicates support for metrics
	FeatureMetrics = "metrics"
	
	// FeatureLogging indicates support for structured logging
	FeatureLogging = "logging"
	
	// FeatureDebug indicates support for debug mode
	FeatureDebug = "debug"
	
	// FeatureHealthCheck indicates support for health checks
	FeatureHealthCheck = "health_check"
	
	// FeatureHotReload indicates support for hot reloading
	FeatureHotReload = "hot_reload"
	
	// FeatureRateLimiting indicates support for rate limiting
	FeatureRateLimiting = "rate_limiting"
	
	// FeatureCircuitBreaker indicates support for circuit breaking
	FeatureCircuitBreaker = "circuit_breaker"
	
	// FeatureRetry indicates support for retry logic
	FeatureRetry = "retry"
	
	// FeatureTimeout indicates support for timeout handling
	FeatureTimeout = "timeout"
	
	// FeatureCaching indicates support for caching
	FeatureCaching = "caching"
	
	// FeatureBulkhead indicates support for bulkhead pattern
	FeatureBulkhead = "bulkhead"
	
	// FeatureObservability indicates support for observability
	FeatureObservability = "observability"
)