package bruteforce

import (
	"context"
	"fmt"
	"sync"
	"time"

	"log/slog"

	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/log"
)

// ProtectionManager is the main implementation of the ProtectionService interface
type ProtectionManager struct {
	storage       Storage
	config        *Config
	notification  NotificationService
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	mu            sync.RWMutex
	logger        *slog.Logger
}

// NewProtectionManager creates a new ProtectionManager
func NewProtectionManager(
	storage Storage,
	config *Config,
	notification NotificationService,
) *ProtectionManager {
	if config == nil {
		config = DefaultConfig()
	}

	manager := &ProtectionManager{
		storage:      storage,
		config:       config,
		notification: notification,
		stopChan:     make(chan struct{}),
		logger:       log.Default().Logger.With(slog.String("component", "bruteforce")),
	}

	// Start cleanup routine if auto-unlock is enabled
	if config.AutoUnlock {
		manager.startCleanupRoutine()
	}

	return manager
}

// CheckAttempt checks if a login attempt should be allowed
func (m *ProtectionManager) CheckAttempt(
	ctx context.Context,
	userID, username, ipAddress, provider string,
) (AttemptStatus, *AccountLock, error) {
	// First check if the account is locked
	if userID != "" {
		isLocked, lock, err := m.IsLocked(ctx, userID)
		if err != nil {
			return StatusAllowed, nil, err
		}

		if isLocked {
			return StatusLockedOut, lock, nil
		}
	}

	// Check IP-based rate limiting
	if ipAddress != "" && m.config.IPRateLimit > 0 {
		ipCount, err := m.storage.CountRecentIPAttempts(
			ctx,
			ipAddress,
			time.Now().Add(-m.config.IPRateLimitWindow),
		)
		if err != nil {
			return StatusAllowed, nil, err
		}

		if ipCount >= m.config.IPRateLimit {
			return StatusRateLimited, nil, nil
		}
	}

	// Check global rate limiting
	if m.config.GlobalRateLimit > 0 {
		globalCount, err := m.storage.CountRecentGlobalAttempts(
			ctx,
			time.Now().Add(-m.config.GlobalRateLimitWindow),
		)
		if err != nil {
			return StatusAllowed, nil, err
		}

		if globalCount >= m.config.GlobalRateLimit {
			return StatusRateLimited, nil, nil
		}
	}

	return StatusAllowed, nil, nil
}

// RecordAttempt records a login attempt
func (m *ProtectionManager) RecordAttempt(ctx context.Context, attempt *LoginAttempt) error {
	if attempt == nil {
		return errors.InvalidArgument("attempt", "cannot be nil")
	}

	// Record the attempt
	if err := m.storage.RecordAttempt(ctx, attempt); err != nil {
		return err
	}

	// Check if we need to lock the account
	if !attempt.Successful && attempt.UserID != "" {
		failedAttempts, err := m.storage.CountRecentFailedAttempts(
			ctx,
			attempt.UserID,
			time.Now().Add(-m.config.AttemptWindowDuration),
		)
		if err != nil {
			return err
		}

		if failedAttempts >= m.config.MaxAttempts {
			reason := fmt.Sprintf("Too many failed login attempts (%d/%d)", failedAttempts, m.config.MaxAttempts)
			_, err := m.LockAccount(ctx, attempt.UserID, attempt.Username, reason)
			if err != nil {
				return err
			}
		}
	}

	// If successful and configured to reset attempts, clear the failed attempt count
	if attempt.Successful && attempt.UserID != "" && m.config.ResetAttemptsOnSuccess {
		// We don't actually clear previous attempts from storage, just record a successful one
		// The count of failed attempts will be zero in the time window after this success
		m.logger.Debug("Reset failed attempts counter due to successful login", 
			slog.String("user_id", attempt.UserID),
			slog.String("auth_provider", attempt.AuthProvider))
	}

	return nil
}

// LockAccount locks a user account
func (m *ProtectionManager) LockAccount(ctx context.Context, userID, username, reason string) (*AccountLock, error) {
	if userID == "" {
		return nil, errors.InvalidArgument("userID", "cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check current lock count to potentially increase lockout duration
	var lockoutCount int
	lockHistory, err := m.storage.GetLockHistory(ctx, userID)
	if err != nil {
		return nil, err
	}
	
	// Use the length of history, but if there are previous locks, 
	// use the highest lockout count to properly increment
	if len(lockHistory) > 0 {
		// Find the highest lockout count from previous locks
		for _, prevLock := range lockHistory {
			if prevLock.LockoutCount > lockoutCount {
				lockoutCount = prevLock.LockoutCount
			}
		}
	} else {
		lockoutCount = 0 // First lock for this user
	}

	// Calculate unlock time
	var unlockDuration time.Duration
	if m.config.IncreaseTimeFactor && lockoutCount > 0 {
		// Increase lockout duration exponentially with each consecutive lockout
		// but cap it at 24 hours to prevent excessive lockouts
		factor := 1 << uint(lockoutCount-1) // 2^(lockoutCount-1)
		if factor > 96 {                    // Cap at 96 (24 hours for 15 min base)
			factor = 96
		}
		unlockDuration = m.config.LockoutDuration * time.Duration(factor)
	} else {
		unlockDuration = m.config.LockoutDuration
	}

	now := time.Now()
	lock := &AccountLock{
		UserID:       userID,
		Username:     username,
		Reason:       reason,
		LockTime:     now,
		UnlockTime:   now.Add(unlockDuration),
		LockoutCount: lockoutCount + 1,
	}

	// Store the lock
	if err := m.storage.CreateLock(ctx, lock); err != nil {
		return nil, err
	}

	// Send notification if configured
	if m.notification != nil && m.config.EmailNotification {
		if err := m.notification.NotifyLockout(ctx, lock); err != nil {
			// Log the error but don't fail the operation
			m.logger.Error("Failed to send lockout notification", 
				slog.String("user_id", userID),
				slog.String("error", err.Error()))
		}
	}

	m.logger.Info("Account locked", 
		slog.String("user_id", userID),
		slog.String("username", username),
		slog.String("reason", reason),
		slog.Time("unlock_time", lock.UnlockTime),
		slog.Int("lockout_count", lock.LockoutCount))

	return lock, nil
}

// UnlockAccount unlocks a user account
func (m *ProtectionManager) UnlockAccount(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.InvalidArgument("userID", "cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if the account is locked
	lock, err := m.storage.GetLock(ctx, userID)
	if err != nil {
		return err
	}

	if lock == nil {
		return nil // Already unlocked
	}

	// Delete the lock
	if err := m.storage.DeleteLock(ctx, userID); err != nil {
		return err
	}

	m.logger.Info("Account unlocked", 
		slog.String("user_id", userID),
		slog.String("username", lock.Username))

	return nil
}

// IsLocked checks if a user account is locked
func (m *ProtectionManager) IsLocked(ctx context.Context, userID string) (bool, *AccountLock, error) {
	if userID == "" {
		return false, nil, errors.InvalidArgument("userID", "cannot be empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	lock, err := m.storage.GetLock(ctx, userID)
	if err != nil {
		return false, nil, err
	}

	if lock == nil {
		return false, nil, nil
	}

	// Check if the lock has expired
	if m.config.AutoUnlock && time.Now().After(lock.UnlockTime) {
		// The lock has expired, but we don't remove it here to avoid a race condition
		// It will be removed by the cleanup routine
		return false, nil, nil
	}

	return true, lock, nil
}

// GetLockHistory gets the lock history for a user
func (m *ProtectionManager) GetLockHistory(ctx context.Context, userID string) ([]*AccountLock, error) {
	if userID == "" {
		return nil, errors.InvalidArgument("userID", "cannot be empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.storage.GetLockHistory(ctx, userID)
}

// GetAttemptHistory gets the attempt history for a user
func (m *ProtectionManager) GetAttemptHistory(ctx context.Context, userID string, limit int) ([]*LoginAttempt, error) {
	if userID == "" {
		return nil, errors.InvalidArgument("userID", "cannot be empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get all attempts for user
	attempts, err := m.storage.GetAttempts(ctx, userID, time.Time{})
	if err != nil {
		return nil, err
	}

	// Sort attempts by timestamp, most recent first (we don't assume storage implementation does this)
	// Use a simple insertion sort since the number of attempts is likely small
	for i := 1; i < len(attempts); i++ {
		j := i
		for j > 0 && attempts[j-1].Timestamp.Before(attempts[j].Timestamp) {
			attempts[j], attempts[j-1] = attempts[j-1], attempts[j]
			j--
		}
	}

	// Apply limit
	if limit > 0 && len(attempts) > limit {
		attempts = attempts[:limit]
	}

	return attempts, nil
}

// Cleanup removes expired locks and old attempts
func (m *ProtectionManager) Cleanup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Delete expired locks
	if err := m.storage.DeleteExpiredLocks(ctx); err != nil {
		return err
	}

	// Delete old attempts (keep attempts for 30 days)
	cutoff := time.Now().AddDate(0, 0, -30)
	if err := m.storage.DeleteOldAttempts(ctx, cutoff); err != nil {
		return err
	}

	m.logger.Debug("Cleanup completed", 
		slog.Time("cutoff_time", cutoff))

	return nil
}

// startCleanupRoutine starts a background goroutine to clean up expired locks
func (m *ProtectionManager) startCleanupRoutine() {
	m.cleanupTicker = time.NewTicker(m.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-m.cleanupTicker.C:
				ctx := context.Background()
				if err := m.Cleanup(ctx); err != nil {
					m.logger.Error("Cleanup routine error", 
						slog.String("error", err.Error()))
				}
			case <-m.stopChan:
				m.cleanupTicker.Stop()
				return
			}
		}
	}()

	m.logger.Debug("Cleanup routine started", 
		slog.Duration("interval", m.config.CleanupInterval))
}

// Stop stops the protection manager and any background routines
func (m *ProtectionManager) Stop() {
	if m.cleanupTicker != nil {
		close(m.stopChan)
		m.logger.Debug("Cleanup routine stopped")
	}
}