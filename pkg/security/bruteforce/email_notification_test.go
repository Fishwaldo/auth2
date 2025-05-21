package bruteforce_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/security/bruteforce"
)

func TestEmailNotificationService_NotifyLockout(t *testing.T) {
	// Create mock email sender
	emailSender := bruteforce.NewMockEmailSender()
	config := bruteforce.DefaultEmailConfig()

	// Create notification service
	service := bruteforce.NewEmailNotificationService(emailSender, config)

	// Create a test lock
	lock := &bruteforce.AccountLock{
		UserID:       "email-test-user",
		Username:     "emailtestuser",
		Reason:       "Too many failed login attempts",
		LockTime:     time.Now(),
		UnlockTime:   time.Now().Add(15 * time.Minute),
		LockoutCount: 1,
	}

	// Call NotifyLockout
	err := service.NotifyLockout(context.Background(), lock)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check that an email was sent
	emails := emailSender.GetSentEmails()
	if len(emails) != 1 {
		t.Fatalf("Expected 1 email, got %d", len(emails))
	}

	// Check email details
	email := emails[0]
	if email.From != config.FromAddress {
		t.Errorf("Expected email to be sent from %s, got %s", config.FromAddress, email.From)
	}
	if !strings.Contains(email.Body, lock.Username) {
		t.Errorf("Expected email body to contain username %s", lock.Username)
	}
	if !strings.Contains(email.Body, lock.Reason) {
		t.Errorf("Expected email body to contain reason %s", lock.Reason)
	}

	// Test with nil lock
	err = service.NotifyLockout(context.Background(), nil)
	if err == nil {
		t.Errorf("Expected error for nil lock, got nil")
	}
}