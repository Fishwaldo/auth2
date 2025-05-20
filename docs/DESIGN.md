# Auth2 Library Design Document

## Overview

Auth2 is a comprehensive, modular authentication library for Go applications. It provides a complete solution for user authentication, authorization, session management, and user data handling with a focus on security, flexibility, and ease of integration.

## Core Architecture

The library follows hexagonal/clean architecture principles to maintain separation of concerns and enable high modularity:

1. **Domain Layer**: Core entities and business rules
2. **Application Layer**: Use cases and application logic
3. **Infrastructure Layer**: External systems integration and adapters
4. **Interface Layer**: HTTP and framework integration

### Key Design Principles

1. Interface-driven design for all components
2. Dependency injection for loose coupling
3. Clear error handling with descriptive errors
4. Comprehensive logging with context
5. Thread-safe implementations

## Package Structure

```
github.com/Fishwaldo/auth2/
├── pkg/
│   ├── auth/                     # Core authentication logic
│   │   ├── providers/            # Authentication providers
│   │   │   ├── basic/            # Username/password
│   │   │   ├── oauth/            # OAuth providers
│   │   │   │   ├── google/       # Google OAuth
│   │   │   │   ├── github/       # GitHub OAuth
│   │   │   │   ├── microsoft/    # Microsoft OAuth
│   │   │   │   └── facebook/     # Facebook OAuth
│   │   │   └── saml/             # SAML implementation
│   │   ├── mfa/                  # MFA implementations
│   │   │   ├── totp/             # Time-based OTP
│   │   │   ├── webauthn/         # WebAuthn/FIDO2
│   │   │   ├── email/            # Email OTP
│   │   │   └── backupcodes/      # Backup codes
│   │   └── verification/         # Account verification
│   │       ├── email/            # Email verification
│   │       └── providers/        # Email providers
│   ├── session/                  # Session management
│   │   ├── cookie/               # Cookie-based sessions
│   │   ├── jwt/                  # JWT token authentication
│   │   └── token/                # Bearer token authentication
│   ├── user/                     # User management
│   │   ├── profile/              # User profile handling
│   │   └── password/             # Password management
│   ├── rbac/                     # Role-based access control
│   │   ├── role/                 # Role management
│   │   ├── permission/           # Permission management
│   │   └── group/                # Group management
│   ├── storage/                  # Storage interfaces
│   │   ├── sql/                  # Standard SQL implementation
│   │   ├── gorm/                 # GORM implementation
│   │   ├── ent/                  # Ent implementation
│   │   └── memory/               # In-memory implementation
│   ├── cache/                    # Cache interfaces and implementations
│   │   └── redis/                # Redis cache implementation
│   ├── http/                     # HTTP framework adapters
│   │   ├── std/                  # Standard library
│   │   ├── chi/                  # Chi router
│   │   ├── echo/                 # Echo framework
│   │   ├── fiber/                # Fiber
│   │   ├── gin/                  # Gin
│   │   ├── gorilla/              # Gorilla mux
│   │   ├── httprouter/           # httprouter
│   │   ├── huma/                 # Huma
│   │   └── fasthttp/             # FastHTTP
│   ├── security/                 # Security features
│   │   ├── ratelimit/            # Rate limiting
│   │   ├── csrf/                 # CSRF protection
│   │   ├── bruteforce/           # Brute force protection
│   │   └── recovery/             # Account recovery
│   ├── config/                   # Configuration
│   └── log/                      # Logging utilities
├── internal/                     # Internal implementation details
│   ├── utils/                    # Utility functions
│   └── errors/                   # Error definitions
├── test/                         # Integration tests
│   └── mocks/                    # Mock implementations
└── examples/                     # Example integrations
    ├── basic/                    # Simple integration
    ├── complete/                 # Complete implementation
    └── custom/                   # Custom provider implementation
```

## Core Components Design

### Authentication Provider Interface

```go
type AuthProvider interface {
    // Authenticate verifies user credentials and returns a user ID if successful
    Authenticate(ctx context.Context, credentials interface{}) (string, error)
    
    // Supports returns true if this provider supports the given credentials type
    Supports(credentials interface{}) bool
    
    // GetID returns the unique identifier for this provider
    GetID() string
    
    // Initialize sets up the provider with necessary configuration
    Initialize(config interface{}) error
}
```

### MFA Provider Interface

```go
type MFAProvider interface {
    // Setup initializes the MFA method for a user
    Setup(ctx context.Context, userID string) (SetupData, error)
    
    // Verify checks if the provided code is valid
    Verify(ctx context.Context, userID string, code string) (bool, error)
    
    // GetID returns the unique identifier for this MFA provider
    GetID() string
    
    // Initialize sets up the provider with necessary configuration
    Initialize(config interface{}) error
}
```

### Dual-Mode Providers

Some authentication methods like FIDO2/WebAuthn can function both as primary authentication and as MFA methods. These providers implement both interfaces:

```go
// DualModeProvider implements both AuthProvider and MFAProvider interfaces
type DualModeProvider interface {
    AuthProvider
    MFAProvider
}
```

This design allows WebAuthn/FIDO2 to be used either as a standalone authentication method (passwordless) or as a second factor alongside another authentication method.

### Storage Interface

```go
type UserStore interface {
    // CreateUser creates a new user
    CreateUser(ctx context.Context, user User) (string, error)
    
    // GetUser retrieves a user by ID
    GetUser(ctx context.Context, userID string) (User, error)
    
    // GetUserByUsername retrieves a user by username
    GetUserByUsername(ctx context.Context, username string) (User, error)
    
    // UpdateUser updates an existing user
    UpdateUser(ctx context.Context, user User) error
    
    // DeleteUser deletes a user
    DeleteUser(ctx context.Context, userID string) error
    
    // GetUserProfile gets a user's profile data
    GetUserProfile(ctx context.Context, userID string) (map[string]interface{}, error)
    
    // UpdateUserProfile updates a user's profile data
    UpdateUserProfile(ctx context.Context, userID string, profile map[string]interface{}) error
}
```

### Session Management Interface

```go
type SessionManager interface {
    // CreateSession creates a new session for a user
    CreateSession(ctx context.Context, userID string, data map[string]interface{}) (Session, error)
    
    // GetSession retrieves a session by ID
    GetSession(ctx context.Context, sessionID string) (Session, error)
    
    // RefreshSession extends the session lifetime
    RefreshSession(ctx context.Context, sessionID string) error
    
    // RevokeSession invalidates a session
    RevokeSession(ctx context.Context, sessionID string) error
    
    // RevokeAllUserSessions invalidates all sessions for a user
    RevokeAllUserSessions(ctx context.Context, userID string) error
}
```

### RBAC Interface

```go
type RBACManager interface {
    // CreateRole creates a new role
    CreateRole(ctx context.Context, role Role) (string, error)
    
    // GetRole retrieves a role by ID
    GetRole(ctx context.Context, roleID string) (Role, error)
    
    // UpdateRole updates an existing role
    UpdateRole(ctx context.Context, role Role) error
    
    // DeleteRole deletes a role
    DeleteRole(ctx context.Context, roleID string) error
    
    // AssignRoleToUser assigns a role to a user
    AssignRoleToUser(ctx context.Context, userID, roleID string) error
    
    // RevokeRoleFromUser revokes a role from a user
    RevokeRoleFromUser(ctx context.Context, userID, roleID string) error
    
    // HasPermission checks if a user has a specific permission
    HasPermission(ctx context.Context, userID, permission string) (bool, error)
}
```

## HTTP Framework Integration

Each HTTP framework adapter will implement the following interface:

```go
type HTTPAdapter interface {
    // Middleware returns middleware for the specific framework
    Middleware() interface{}
    
    // RegisterRoutes registers authentication routes
    RegisterRoutes() error
    
    // ParseRequest extracts authentication data from requests
    ParseRequest(request interface{}) (AuthData, error)
    
    // WriteResponse writes authentication responses
    WriteResponse(response interface{}, data interface{}) error
}
```

## Security Features Implementation

### Rate Limiting

```go
type RateLimiter interface {
    // Allow checks if the operation is allowed based on the key
    Allow(ctx context.Context, key string) (bool, error)
    
    // Reset resets the counter for a key
    Reset(ctx context.Context, key string) error
}
```

### CSRF Protection

```go
type CSRFProtector interface {
    // GenerateToken generates a new CSRF token
    GenerateToken(ctx context.Context, userID string) (string, error)
    
    // ValidateToken validates a CSRF token
    ValidateToken(ctx context.Context, userID, token string) (bool, error)
}
```

## Main Package API

```go
// Auth2 is the main entry point for the library
type Auth2 struct {
    // Configuration
    Config *Config
    
    // User management
    UserManager *user.Manager
    
    // Authentication
    AuthManager *auth.Manager
    
    // Session management
    SessionManager session.Manager
    
    // RBAC
    RBACManager rbac.Manager
    
    // Security features
    Security *security.Manager
}

// New creates a new Auth2 instance with the provided configuration
func New(config *Config) (*Auth2, error) {
    // Initialize all components
    // ...
}

// RegisterHTTPAdapter registers an HTTP framework adapter
func (a *Auth2) RegisterHTTPAdapter(adapter http.Adapter) error {
    // Register adapter
    // ...
}

// RegisterAuthProvider registers an authentication provider
func (a *Auth2) RegisterAuthProvider(provider auth.Provider) error {
    // Register provider
    // ...
}

// RegisterMFAProvider registers an MFA provider
func (a *Auth2) RegisterMFAProvider(provider auth.MFAProvider) error {
    // Register provider
    // ...
}

// RegisterStorageAdapter registers a storage adapter
func (a *Auth2) RegisterStorageAdapter(adapter storage.Adapter) error {
    // Register adapter
    // ...
}
```

## Error Handling

All errors will be defined in a central location:

```go
package errors

// Common errors
var (
    ErrUserNotFound        = errors.New("user not found")
    ErrInvalidCredentials  = errors.New("invalid credentials")
    ErrUserDisabled        = errors.New("user account is disabled")
    ErrSessionExpired      = errors.New("session has expired")
    ErrInvalidToken        = errors.New("invalid token")
    ErrPermissionDenied    = errors.New("permission denied")
    ErrRateLimitExceeded   = errors.New("rate limit exceeded")
    ErrInvalidMFACode      = errors.New("invalid MFA code")
    // ...
)
```

## Configuration

```go
// Config holds the configuration for the entire library
type Config struct {
    // General settings
    AppName      string
    Environment  string
    
    // Auth settings
    Auth struct {
        PasswordPolicy         *password.Policy
        SessionDuration        time.Duration
        RequireEmailVerification bool
        MaxLoginAttempts       int
        LockoutDuration        time.Duration
    }
    
    // Storage settings
    Storage struct {
        Type                  string // sql, gorm, ent, memory
        ConnectionString      string
    }
    
    // Security settings
    Security struct {
        CSRFTokenExpiry       time.Duration
        SecureCookies         bool
        SameSite              string
    }
    
    // Logging
    Logger slog.Logger
}
```

## Testing Strategy

1. **Black Box Unit Testing**:
   - Test all components through their public interfaces only
   - Do not test internal implementation details
   - Use table-driven tests for comprehensive coverage
   - Mock all external dependencies
   - Each component must be testable in isolation
   - Test both success and failure scenarios

2. **Integration Testing**:
   - Test integration with all supported storage adapters
   - Test integration with all supported HTTP frameworks
   - Use in-memory implementations where appropriate
   - Focus on contract adherence between components

3. **End-to-End Testing**:
   - Test complete authentication flows
   - Test security features effectiveness
   - Test all public APIs
   - Verify proper error handling and error messages

## Documentation

1. **Package Documentation**:
   - Godoc-compliant documentation for all exported functions and types
   - Usage examples for all major components

2. **Integration Guides**:
   - Step-by-step guides for each supported HTTP framework
   - Configuration examples for different deployment scenarios

3. **API Reference**:
   - Complete API reference with examples
   - OpenAPI specification for REST APIs

4. **Security Recommendations**:
   - Best practices for secure configuration
   - Security considerations for production deployment