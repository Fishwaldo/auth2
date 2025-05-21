package bruteforce

import (
	"context"
	"fmt"
	"sync"
)

// MockUserService is a mock implementation of the UserService interface for testing
type MockUserService struct {
	// users maps user IDs to email addresses
	users map[string]string
	// mu is a mutex to protect concurrent access to users
	mu sync.RWMutex
}

// NewMockUserService creates a new mock user service
func NewMockUserService() *MockUserService {
	return &MockUserService{
		users: make(map[string]string),
	}
}

// GetUserEmail retrieves a user's email address by user ID
func (s *MockUserService) GetUserEmail(ctx context.Context, userID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	email, ok := s.users[userID]
	if !ok {
		return "", fmt.Errorf("user not found: %s", userID)
	}

	return email, nil
}

// AddUser adds a user to the mock service
func (s *MockUserService) AddUser(userID, email string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[userID] = email
}

// RemoveUser removes a user from the mock service
func (s *MockUserService) RemoveUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.users, userID)
}