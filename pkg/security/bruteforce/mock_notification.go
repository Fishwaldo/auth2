package bruteforce

import (
	"context"
	"sync"
)

// MockNotificationService is a mock implementation of the NotificationService interface for testing
type MockNotificationService struct {
	notifications []*AccountLock
	mu            sync.RWMutex
}

// NewMockNotificationService creates a new mock notification service
func NewMockNotificationService() *MockNotificationService {
	return &MockNotificationService{
		notifications: make([]*AccountLock, 0),
	}
}

// NotifyLockout sends a notification about an account lockout
func (m *MockNotificationService) NotifyLockout(ctx context.Context, lock *AccountLock) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.notifications = append(m.notifications, lock)
	return nil
}

// GetNotifications returns all recorded notifications
func (m *MockNotificationService) GetNotifications() []*AccountLock {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Make a copy to avoid race conditions
	result := make([]*AccountLock, len(m.notifications))
	copy(result, m.notifications)
	
	return result
}

// ClearNotifications clears all recorded notifications
func (m *MockNotificationService) ClearNotifications() {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.notifications = make([]*AccountLock, 0)
}