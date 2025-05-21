package bruteforce

import (
	"fmt"

	"github.com/Fishwaldo/auth2/internal/errors"
)

// Error codes specific to bruteforce protection
const (
	ErrCodeAccountLocked     errors.ErrorCode = "account_locked"
	ErrCodeRateLimitExceeded errors.ErrorCode = "rate_limit_exceeded"
)

// Package errors
var (
	// ErrAccountLocked is returned when an account is locked due to too many failed login attempts
	ErrAccountLocked = errors.CreateAuthError(
		ErrCodeAccountLocked,
		"Account is locked due to too many failed login attempts",
	)

	// ErrRateLimitExceeded is returned when an IP address or username has exceeded the rate limit
	ErrRateLimitExceeded = errors.CreateAuthError(
		errors.CodeRateLimited,
		"Rate limit exceeded for login attempts",
	)
)

// WithUserID adds a user ID to an error
func WithUserID(err *errors.Error, userID string) *errors.Error {
	return err.WithDetails(map[string]interface{}{
		"user_id": userID,
	})
}

// WithDuration adds a duration to an error
func WithDuration(err *errors.Error, duration string) *errors.Error {
	return err.WithDetails(map[string]interface{}{
		"lockout_duration": duration,
	})
}

// AccountLockedError creates a detailed account locked error
func AccountLockedError(userID, reason string, unlockTime string) *errors.Error {
	err := ErrAccountLocked.WithDetails(map[string]interface{}{
		"user_id":     userID,
		"reason":      reason,
		"unlock_time": unlockTime,
	})
	
	message := fmt.Sprintf("Account is locked: %s", reason)
	if unlockTime != "" {
		message += fmt.Sprintf(". Unlocks at: %s", unlockTime)
	}
	
	return err.WithMessage(message)
}

// RateLimitError creates a detailed rate limit error
func RateLimitError(identifier string, limit int, timeWindow string) *errors.Error {
	return ErrRateLimitExceeded.WithDetails(map[string]interface{}{
		"identifier":  identifier,
		"limit":       limit,
		"time_window": timeWindow,
	}).WithMessage(fmt.Sprintf("Rate limit of %d attempts per %s exceeded for %s", limit, timeWindow, identifier))
}