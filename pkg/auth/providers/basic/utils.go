package basic

import (
	"context"
	"time"

	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/user"
)

// ValidateAccount performs validation on a user account
// Returns nil if the account is valid, or an error if there are issues
func ValidateAccount(ctx context.Context, usr *user.User, config *Config) error {
	if !usr.Enabled {
		return errors.WrapError(errors.ErrUserDisabled, errors.CodeUserDisabled, "account is disabled")
	}

	if usr.Locked {
		// Check if the lockout period has expired
		if config.AccountLockDuration > 0 && !usr.LockoutTime.IsZero() {
			lockoutExpiry := usr.LockoutTime.Add(time.Duration(config.AccountLockDuration) * time.Minute)
			if time.Now().After(lockoutExpiry) {
				// Lockout period has expired, account can be unlocked
				return nil
			}
		}
		return errors.WrapError(errors.ErrUserLocked, errors.CodeUserLocked, "account is locked")
	}

	if config.RequireVerifiedEmail && !usr.EmailVerified {
		return errors.WrapError(errors.ErrUnauthenticated, errors.CodeEmailNotVerified, 
			"email verification required")
	}

	return nil
}

// CheckPasswordRequirements checks if the user needs to change their password
func CheckPasswordRequirements(usr *user.User) (bool, string) {
	if usr.RequirePasswordChange {
		return true, "Password change required"
	}

	// Additional checks can be added here, such as:
	// - Password expiration
	// - Password policy changes requiring updates
	// - Security incidents requiring password changes

	return false, ""
}

// ProcessSuccessfulLogin updates user information after a successful login
func ProcessSuccessfulLogin(ctx context.Context, userStore user.Store, usr *user.User) error {
	// Reset failed login attempts
	usr.FailedLoginAttempts = 0
	usr.LastLogin = time.Now()

	// Update the user
	return userStore.Update(ctx, usr)
}

// ProcessFailedLogin updates user information after a failed login attempt
func ProcessFailedLogin(ctx context.Context, userStore user.Store, usr *user.User, config *Config) error {
	// Increment failed login attempts
	usr.FailedLoginAttempts++
	usr.LastFailedLogin = time.Now()

	// Check if we need to lock the account
	if config.AccountLockThreshold > 0 && usr.FailedLoginAttempts >= config.AccountLockThreshold {
		usr.Locked = true
		usr.LockoutTime = time.Now()
		usr.LockoutReason = "Too many failed login attempts"
	}

	// Update the user
	return userStore.Update(ctx, usr)
}