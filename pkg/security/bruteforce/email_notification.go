package bruteforce

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Fishwaldo/auth2/pkg/log"
)

// EmailNotificationService is an implementation of the NotificationService interface
// that sends email notifications for account lockouts
type EmailNotificationService struct {
	// emailSender is the service used to send emails
	emailSender EmailSender
	// fromAddress is the email address from which notifications are sent
	fromAddress string
	// lockoutTemplate is the template for lockout notification emails
	lockoutTemplate string
	// logger is the logger for the email notification service
	logger *slog.Logger
}

// EmailSender defines the interface for sending emails
type EmailSender interface {
	// SendEmail sends an email
	SendEmail(ctx context.Context, to, from, subject, body string) error
}

// EmailConfig defines the configuration for the email notification service
type EmailConfig struct {
	// FromAddress is the email address from which notifications are sent
	FromAddress string
	// LockoutSubject is the subject for lockout notification emails
	LockoutSubject string
	// LockoutTemplate is the template for lockout notification emails
	LockoutTemplate string
}

// DefaultEmailConfig returns a default configuration for the email notification service
func DefaultEmailConfig() *EmailConfig {
	return &EmailConfig{
		FromAddress:    "security@example.com",
		LockoutSubject: "Account Security Alert: Your Account Has Been Locked",
		LockoutTemplate: `
Dear User,

Your account with username %s has been locked due to too many failed login attempts.

Reason: %s
Lock Time: %s
Automatic Unlock Time: %s

If you did not attempt to access your account, please contact support immediately as your account may be under attack.

To unlock your account before the automatic unlock time, please use the account recovery process or contact support.

Regards,
Security Team
`,
	}
}

// NewEmailNotificationService creates a new email notification service
func NewEmailNotificationService(emailSender EmailSender, config *EmailConfig) *EmailNotificationService {
	if config == nil {
		config = DefaultEmailConfig()
	}

	return &EmailNotificationService{
		emailSender:     emailSender,
		fromAddress:     config.FromAddress,
		lockoutTemplate: config.LockoutTemplate,
		logger:          log.Default().Logger.With(slog.String("component", "bruteforce.notification.email")),
	}
}

// NotifyLockout sends a notification about an account lockout
func (s *EmailNotificationService) NotifyLockout(ctx context.Context, lock *AccountLock) error {
	if lock == nil {
		return fmt.Errorf("lock cannot be nil")
	}

	// Format the email body
	body := fmt.Sprintf(
		s.lockoutTemplate,
		lock.Username,
		lock.Reason,
		lock.LockTime.Format(time.RFC1123),
		lock.UnlockTime.Format(time.RFC1123),
	)

	// We don't have the user's email address in the AccountLock,
	// so this is a placeholder. In a real implementation, you would 
	// retrieve the user's email address from a user service.
	userEmail := "user@example.com" // Placeholder

	subject := "Account Security Alert: Your Account Has Been Locked"

	// Send the email
	err := s.emailSender.SendEmail(ctx, userEmail, s.fromAddress, subject, body)
	if err != nil {
		s.logger.Error("Failed to send lockout notification email",
			slog.String("user_id", lock.UserID),
			slog.String("username", lock.Username),
			slog.String("error", err.Error()))
		return err
	}

	s.logger.Info("Sent lockout notification email",
		slog.String("user_id", lock.UserID),
		slog.String("username", lock.Username))

	return nil
}