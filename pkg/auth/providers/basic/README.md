# Basic Authentication Provider

This provider implements username/password authentication for the Auth2 library. It handles user login with various security features including account locking, email verification requirements, and password change policies.

## Features

- Username/password authentication
- Account locking after configurable number of failed attempts
- Automatic account unlocking after a configurable time period
- Email verification enforcement
- Password change requirement detection
- Integration with the Auth2 plugin system

## Configuration

The Basic Authentication Provider accepts the following configuration options:

```go
type Config struct {
    // AccountLockThreshold is the number of failed login attempts before an account is locked
    AccountLockThreshold int `json:"account_lock_threshold" yaml:"account_lock_threshold"`

    // AccountLockDuration is the duration (in minutes) for which an account is locked
    AccountLockDuration int `json:"account_lock_duration" yaml:"account_lock_duration"`

    // RequireVerifiedEmail indicates whether email verification is required to authenticate
    RequireVerifiedEmail bool `json:"require_verified_email" yaml:"require_verified_email"`
}
```

Default configuration:
- Account lock threshold: 5 failed attempts
- Account lock duration: 30 minutes
- Require verified email: true

## Usage

### Direct Instantiation

```go
import (
    "github.com/Fishwaldo/auth2/pkg/auth/providers/basic"
    "github.com/Fishwaldo/auth2/pkg/user"
)

// Create the provider with a custom configuration
config := basic.DefaultConfig()
config.AccountLockThreshold = 3 // Lock after 3 failed attempts

provider := basic.NewProvider(
    "basic",
    userStore,        // Implements user.Store
    passwordUtils,    // Implements user.PasswordUtils
    config,
)
```

### Using the Factory

```go
import (
    "github.com/Fishwaldo/auth2/pkg/auth/providers/basic"
)

// Register the provider factory with the registry
err := basic.Register(registry, userStore, passwordUtils)
if err != nil {
    // Handle error
}

// When needed, create a provider instance
provider, err := registry.CreateAuthProvider("basic", map[string]interface{}{
    "account_lock_threshold": 3,
    "account_lock_duration": 60,
    "require_verified_email": true,
})
if err != nil {
    // Handle error
}
```

### Authentication Result

The provider returns an `AuthResult` containing:

- Success status
- User ID (if successful)
- MFA requirement status and available methods
- Additional information like password change requirements
- Error details (if authentication failed)

## Error Handling

The provider returns specific errors for different failure scenarios:

- Invalid credentials
- User not found
- Account disabled
- Account locked
- Email not verified
- Password verification failures

## Integration with MFA

When a user has MFA enabled, a successful username/password authentication will:

1. Indicate MFA is required (`RequiresMFA: true`)
2. Provide a list of enabled MFA methods for the user
3. Require a subsequent MFA verification before completing authentication