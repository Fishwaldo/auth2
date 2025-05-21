# Brute Force Protection

This package provides comprehensive account locking and rate limiting protection against brute force attacks. It can track failed login attempts across different authentication providers and automatically lock accounts after a configurable number of failures.

## Features

- Account locking after configurable number of failed attempts
- Configurable lockout duration with exponential backoff
- Automatic unlocking after lockout duration
- IP-based rate limiting
- Global rate limiting
- Tracking of login attempts with client context
- Lock history and attempt history
- Cleanup mechanism for expired locks and old attempt history
- Notification system for account lockouts

## Usage

### Basic Setup

```go
import (
    "github.com/Fishwaldo/auth2/pkg/security/bruteforce"
)

// Create storage and notification service
storage := bruteforce.NewMemoryStorage()
notification := bruteforce.NewMockNotificationService() // Replace with real implementation

// Create config with desired settings
config := bruteforce.DefaultConfig()
config.MaxAttempts = 5
config.LockoutDuration = 15 * time.Minute

// Create the protection manager
manager := bruteforce.NewProtectionManager(storage, config, notification)

// Create integration helper
authIntegration := bruteforce.NewAuthIntegration(manager)
```

### Integration with Authentication

```go
// Check before authentication
err := authIntegration.CheckBeforeAuthentication(ctx, userID, username, ipAddress, providerID)
if err != nil {
    // Handle locked or rate limited account
    return err
}

// Perform authentication...
authResult := performAuth(...)

// Record the attempt after authentication
err = authIntegration.RecordAuthenticationAttempt(
    ctx, 
    userID, 
    username, 
    ipAddress, 
    providerID, 
    authResult.Success,
    clientInfo,
)
if err != nil {
    // Handle error
}
```

### Manual Lock/Unlock

```go
// Manually lock an account
lock, err := manager.LockAccount(ctx, userID, username, "Manual security lock")
if err != nil {
    // Handle error
}

// Check if an account is locked
isLocked, lockInfo, err := manager.IsLocked(ctx, userID)
if err != nil {
    // Handle error
}

// Manually unlock an account
err = manager.UnlockAccount(ctx, userID)
if err != nil {
    // Handle error
}
```

### Getting History

```go
// Get lock history
lockHistory, err := manager.GetLockHistory(ctx, userID)
if err != nil {
    // Handle error
}

// Get attempt history (limited to last 10 attempts)
attemptHistory, err := manager.GetAttemptHistory(ctx, userID, 10)
if err != nil {
    // Handle error
}
```

## Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| MaxAttempts | Maximum number of failed attempts before locking | 5 |
| LockoutDuration | Duration for which an account is locked | 15 minutes |
| AttemptWindowDuration | Time window during which failed attempts are counted | 30 minutes |
| AutoUnlock | Whether to automatically unlock accounts after LockoutDuration | true |
| CleanupInterval | Interval at which expired locks are cleaned up | 1 hour |
| IncreaseTimeFactor | Whether to increase lockout duration exponentially with repeated lockouts | true |
| IPRateLimit | Number of attempts an IP address can make in IPRateLimitWindow | 20 |
| IPRateLimitWindow | Time window for IP-based rate limiting | 1 hour |
| GlobalRateLimit | Global rate limit for all login attempts | 1000 |
| GlobalRateLimitWindow | Time window for global rate limiting | 1 hour |
| EmailNotification | Whether to send email notifications on account lockout | true |
| ResetAttemptsOnSuccess | Whether to reset failed attempts on successful login | true |

## Storage Interface

You can implement your own storage backend by implementing the `Storage` interface. The package includes an in-memory implementation that can be used for testing or small-scale deployments.

## Notification Interface

You can implement your own notification service by implementing the `NotificationService` interface. The package includes a mock implementation for testing.

## Error Handling

The package provides special error types for account lockouts and rate limiting, which include detailed information about the lockout reason, duration, and other useful metadata.