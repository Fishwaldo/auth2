package bruteforce

import (
	"context"
	"sync"
	"time"
)

// MockEmailSender is a mock implementation of the EmailSender interface for testing
type MockEmailSender struct {
	// emails contains all sent emails
	emails []Email
	// mu is a mutex to protect concurrent access to emails
	mu sync.RWMutex
}

// Email represents an email message
type Email struct {
	// To is the recipient's email address
	To string
	// From is the sender's email address
	From string
	// Subject is the email subject
	Subject string
	// Body is the email body
	Body string
	// SentAt is when the email was sent
	SentAt time.Time
}

// NewMockEmailSender creates a new mock email sender
func NewMockEmailSender() *MockEmailSender {
	return &MockEmailSender{
		emails: make([]Email, 0),
	}
}

// SendEmail sends an email
func (s *MockEmailSender) SendEmail(ctx context.Context, to, from, subject, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.emails = append(s.emails, Email{
		To:      to,
		From:    from,
		Subject: subject,
		Body:    body,
		SentAt:  time.Now(),
	})

	return nil
}

// GetSentEmails returns all sent emails
func (s *MockEmailSender) GetSentEmails() []Email {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Make a copy to avoid race conditions
	result := make([]Email, len(s.emails))
	copy(result, s.emails)

	return result
}

// ClearEmails clears all sent emails
func (s *MockEmailSender) ClearEmails() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.emails = make([]Email, 0)
}