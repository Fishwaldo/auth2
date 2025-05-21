package bruteforce_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/security/bruteforce"
)

func TestNotificationManager_NotifyLockout(t *testing.T) {
	// Create mock user service and email sender
	userService := bruteforce.NewMockUserService()
	emailSender := bruteforce.NewMockEmailSender()
	config := bruteforce.DefaultNotificationConfig()

	// Add a test user
	userService.AddUser("test-user-id", "test@example.com")

	// Create notification manager
	manager := bruteforce.NewNotificationManager(userService, emailSender, config)

	// Create a test lock
	lock := &bruteforce.AccountLock{
		UserID:       "test-user-id",
		Username:     "testuser",
		Reason:       "Too many failed login attempts",
		LockTime:     time.Now(),
		UnlockTime:   time.Now().Add(15 * time.Minute),
		LockoutCount: 1,
	}

	// Call NotifyLockout
	err := manager.NotifyLockout(context.Background(), lock)
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
	if email.To != "test@example.com" {
		t.Errorf("Expected email to be sent to test@example.com, got %s", email.To)
	}
	if email.From != config.EmailConfig.FromAddress {
		t.Errorf("Expected email to be sent from %s, got %s", config.EmailConfig.FromAddress, email.From)
	}
	if email.Subject != config.EmailConfig.LockoutSubject {
		t.Errorf("Expected email subject to be %s, got %s", config.EmailConfig.LockoutSubject, email.Subject)
	}
	if !strings.Contains(email.Body, lock.Username) {
		t.Errorf("Expected email body to contain username %s", lock.Username)
	}
	if !strings.Contains(email.Body, lock.Reason) {
		t.Errorf("Expected email body to contain reason %s", lock.Reason)
	}

	// Test with non-existent user
	nonExistentLock := &bruteforce.AccountLock{
		UserID:       "non-existent-user",
		Username:     "nonexistentuser",
		Reason:       "Too many failed login attempts",
		LockTime:     time.Now(),
		UnlockTime:   time.Now().Add(15 * time.Minute),
		LockoutCount: 1,
	}

	// Call NotifyLockout with non-existent user
	err = manager.NotifyLockout(context.Background(), nonExistentLock)
	if err == nil {
		t.Errorf("Expected error for non-existent user, got nil")
	}
}

func TestNotificationManager_NilEmailSender(t *testing.T) {
	// Create manager with nil email sender
	userService := bruteforce.NewMockUserService()
	config := bruteforce.DefaultNotificationConfig()
	manager := bruteforce.NewNotificationManager(userService, nil, config)

	// Add a test user
	userService.AddUser("test-user-id", "test@example.com")

	// Create a test lock
	lock := &bruteforce.AccountLock{
		UserID:       "test-user-id",
		Username:     "testuser",
		Reason:       "Too many failed login attempts",
		LockTime:     time.Now(),
		UnlockTime:   time.Now().Add(15 * time.Minute),
		LockoutCount: 1,
	}

	// Call NotifyLockout - should not error with nil email sender
	err := manager.NotifyLockout(context.Background(), lock)
	if err != nil {
		t.Fatalf("Unexpected error with nil email sender: %v", err)
	}
}