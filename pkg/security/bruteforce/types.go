package bruteforce

import (
	"context"
	"time"
)

// AttemptStatus represents the status of a login attempt check
type AttemptStatus int

const (
	// StatusAllowed indicates the attempt is allowed
	StatusAllowed AttemptStatus = iota

	// StatusRateLimited indicates the attempt is not allowed due to rate limiting
	StatusRateLimited

	// StatusLockedOut indicates the attempt is not allowed due to account lockout
	StatusLockedOut
)

// LoginAttempt represents a login attempt
type LoginAttempt struct {
	// UserID is the ID of the user for which the login attempt was made
	UserID string

	// Username is the username used in the login attempt
	Username string

	// IPAddress is the IP address from which the login attempt was made
	IPAddress string

	// Timestamp is when the login attempt occurred
	Timestamp time.Time

	// Successful indicates if the login attempt was successful
	Successful bool

	// AuthProvider is the authentication provider used for the login attempt
	AuthProvider string

	// ClientInfo contains additional information about the client
	ClientInfo map[string]string
}

// AccountLock represents an account lockout
type AccountLock struct {
	// UserID is the ID of the user whose account is locked
	UserID string

	// Username is the username of the locked account
	Username string

	// Reason is the reason for the lockout
	Reason string

	// LockTime is when the account was locked
	LockTime time.Time

	// UnlockTime is when the account will be automatically unlocked
	UnlockTime time.Time

	// LockoutCount is the number of times this account has been locked
	LockoutCount int
}

// ProtectionService defines the interface for bruteforce protection operations
type ProtectionService interface {
	// CheckAttempt checks if a login attempt should be allowed
	CheckAttempt(ctx context.Context, userID, username, ipAddress, provider string) (AttemptStatus, *AccountLock, error)

	// RecordAttempt records a login attempt
	RecordAttempt(ctx context.Context, attempt *LoginAttempt) error

	// LockAccount locks a user account
	LockAccount(ctx context.Context, userID, username, reason string) (*AccountLock, error)

	// UnlockAccount unlocks a user account
	UnlockAccount(ctx context.Context, userID string) error

	// IsLocked checks if a user account is locked
	IsLocked(ctx context.Context, userID string) (bool, *AccountLock, error)

	// GetLockHistory gets the lock history for a user
	GetLockHistory(ctx context.Context, userID string) ([]*AccountLock, error)

	// GetAttemptHistory gets the attempt history for a user
	GetAttemptHistory(ctx context.Context, userID string, limit int) ([]*LoginAttempt, error)

	// Cleanup removes expired locks and old attempts
	Cleanup(ctx context.Context) error
}

// Storage defines the interface for bruteforce protection data storage
type Storage interface {
	// RecordAttempt records a login attempt
	RecordAttempt(ctx context.Context, attempt *LoginAttempt) error

	// GetAttempts gets all login attempts for a user within a time window
	GetAttempts(ctx context.Context, userID string, since time.Time) ([]*LoginAttempt, error)

	// CountRecentFailedAttempts counts failed login attempts for a user within a time window
	CountRecentFailedAttempts(ctx context.Context, userID string, since time.Time) (int, error)

	// CountRecentIPAttempts counts login attempts from an IP address within a time window
	CountRecentIPAttempts(ctx context.Context, ipAddress string, since time.Time) (int, error)

	// CountRecentGlobalAttempts counts all login attempts within a time window
	CountRecentGlobalAttempts(ctx context.Context, since time.Time) (int, error)

	// CreateLock creates an account lock
	CreateLock(ctx context.Context, lock *AccountLock) error

	// GetLock gets the current lock for a user
	GetLock(ctx context.Context, userID string) (*AccountLock, error)

	// GetActiveLocks gets all active locks
	GetActiveLocks(ctx context.Context) ([]*AccountLock, error)

	// GetLockHistory gets all locks for a user
	GetLockHistory(ctx context.Context, userID string) ([]*AccountLock, error)

	// DeleteLock deletes a lock for a user
	DeleteLock(ctx context.Context, userID string) error

	// DeleteExpiredLocks deletes all expired locks
	DeleteExpiredLocks(ctx context.Context) error

	// DeleteOldAttempts deletes login attempts older than a given time
	DeleteOldAttempts(ctx context.Context, before time.Time) error
}

// NotificationService defines the interface for sending notifications about account lockouts
type NotificationService interface {
	// NotifyLockout sends a notification about an account lockout
	NotifyLockout(ctx context.Context, lock *AccountLock) error
}