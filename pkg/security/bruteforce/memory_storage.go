package bruteforce

import (
	"context"
	"sync"
	"time"

	"github.com/Fishwaldo/auth2/internal/errors"
)

// MemoryStorage is an in-memory implementation of the Storage interface
type MemoryStorage struct {
	attempts map[string][]*LoginAttempt // userID -> attempts
	ipAttempts map[string][]*LoginAttempt // ipAddress -> attempts
	locks map[string]*AccountLock // userID -> lock
	lockHistory map[string][]*AccountLock // userID -> lock history
	mu sync.RWMutex
}

// NewMemoryStorage creates a new in-memory storage
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		attempts: make(map[string][]*LoginAttempt),
		ipAttempts: make(map[string][]*LoginAttempt),
		locks: make(map[string]*AccountLock),
		lockHistory: make(map[string][]*AccountLock),
	}
}

// RecordAttempt records a login attempt
func (s *MemoryStorage) RecordAttempt(ctx context.Context, attempt *LoginAttempt) error {
	if attempt == nil {
		return errors.InvalidArgument("attempt", "cannot be nil")
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Record attempt for user
	if attempt.UserID != "" {
		s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	}
	
	// Record attempt for IP address
	if attempt.IPAddress != "" {
		s.ipAttempts[attempt.IPAddress] = append(s.ipAttempts[attempt.IPAddress], attempt)
	}
	
	return nil
}

// GetAttempts gets all login attempts for a user within a time window
func (s *MemoryStorage) GetAttempts(ctx context.Context, userID string, since time.Time) ([]*LoginAttempt, error) {
	if userID == "" {
		return nil, errors.InvalidArgument("userID", "cannot be empty")
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	userAttempts, ok := s.attempts[userID]
	if !ok {
		return []*LoginAttempt{}, nil
	}
	
	var recentAttempts []*LoginAttempt
	for _, attempt := range userAttempts {
		if attempt.Timestamp.After(since) || attempt.Timestamp.Equal(since) {
			recentAttempts = append(recentAttempts, attempt)
		}
	}
	
	return recentAttempts, nil
}

// CountRecentFailedAttempts counts failed login attempts for a user within a time window
func (s *MemoryStorage) CountRecentFailedAttempts(ctx context.Context, userID string, since time.Time) (int, error) {
	if userID == "" {
		return 0, errors.InvalidArgument("userID", "cannot be empty")
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	userAttempts, ok := s.attempts[userID]
	if !ok {
		return 0, nil
	}
	
	var count int
	for _, attempt := range userAttempts {
		if !attempt.Successful && (attempt.Timestamp.After(since) || attempt.Timestamp.Equal(since)) {
			count++
		}
	}
	
	return count, nil
}

// CountRecentIPAttempts counts login attempts from an IP address within a time window
func (s *MemoryStorage) CountRecentIPAttempts(ctx context.Context, ipAddress string, since time.Time) (int, error) {
	if ipAddress == "" {
		return 0, errors.InvalidArgument("ipAddress", "cannot be empty")
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	ipAttempts, ok := s.ipAttempts[ipAddress]
	if !ok {
		return 0, nil
	}
	
	var count int
	for _, attempt := range ipAttempts {
		if attempt.Timestamp.After(since) || attempt.Timestamp.Equal(since) {
			count++
		}
	}
	
	return count, nil
}

// CountRecentGlobalAttempts counts all login attempts within a time window
func (s *MemoryStorage) CountRecentGlobalAttempts(ctx context.Context, since time.Time) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var count int
	
	// Count all attempts across all IP addresses
	for _, attempts := range s.ipAttempts {
		for _, attempt := range attempts {
			if attempt.Timestamp.After(since) || attempt.Timestamp.Equal(since) {
				count++
			}
		}
	}
	
	return count, nil
}

// CreateLock creates an account lock
func (s *MemoryStorage) CreateLock(ctx context.Context, lock *AccountLock) error {
	if lock == nil {
		return errors.InvalidArgument("lock", "cannot be nil")
	}
	if lock.UserID == "" {
		return errors.InvalidArgument("lock.UserID", "cannot be empty")
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Store the current lock
	s.locks[lock.UserID] = lock
	
	// Add to lock history
	s.lockHistory[lock.UserID] = append(s.lockHistory[lock.UserID], lock)
	
	return nil
}

// GetLock gets the current lock for a user
func (s *MemoryStorage) GetLock(ctx context.Context, userID string) (*AccountLock, error) {
	if userID == "" {
		return nil, errors.InvalidArgument("userID", "cannot be empty")
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	lock, ok := s.locks[userID]
	if !ok {
		return nil, nil
	}
	
	return lock, nil
}

// GetActiveLocks gets all active locks
func (s *MemoryStorage) GetActiveLocks(ctx context.Context) ([]*AccountLock, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var activeLocks []*AccountLock
	for _, lock := range s.locks {
		activeLocks = append(activeLocks, lock)
	}
	
	return activeLocks, nil
}

// GetLockHistory gets all locks for a user
func (s *MemoryStorage) GetLockHistory(ctx context.Context, userID string) ([]*AccountLock, error) {
	if userID == "" {
		return nil, errors.InvalidArgument("userID", "cannot be empty")
	}
	
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	history, ok := s.lockHistory[userID]
	if !ok {
		return []*AccountLock{}, nil
	}
	
	return history, nil
}

// DeleteLock deletes a lock for a user
func (s *MemoryStorage) DeleteLock(ctx context.Context, userID string) error {
	if userID == "" {
		return errors.InvalidArgument("userID", "cannot be empty")
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	delete(s.locks, userID)
	
	return nil
}

// DeleteExpiredLocks deletes all expired locks
func (s *MemoryStorage) DeleteExpiredLocks(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	
	// Find and remove expired locks
	for userID, lock := range s.locks {
		if lock.UnlockTime.Before(now) {
			delete(s.locks, userID)
		}
	}
	
	return nil
}

// DeleteOldAttempts deletes login attempts older than a given time
func (s *MemoryStorage) DeleteOldAttempts(ctx context.Context, before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Clean up user attempts
	for userID, attempts := range s.attempts {
		var newAttempts []*LoginAttempt
		for _, attempt := range attempts {
			if attempt.Timestamp.After(before) {
				newAttempts = append(newAttempts, attempt)
			}
		}
		if len(newAttempts) == 0 {
			delete(s.attempts, userID)
		} else {
			s.attempts[userID] = newAttempts
		}
	}
	
	// Clean up IP attempts
	for ipAddress, attempts := range s.ipAttempts {
		var newAttempts []*LoginAttempt
		for _, attempt := range attempts {
			if attempt.Timestamp.After(before) {
				newAttempts = append(newAttempts, attempt)
			}
		}
		if len(newAttempts) == 0 {
			delete(s.ipAttempts, ipAddress)
		} else {
			s.ipAttempts[ipAddress] = newAttempts
		}
	}
	
	return nil
}