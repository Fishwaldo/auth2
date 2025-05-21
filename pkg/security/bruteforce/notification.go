package bruteforce

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Fishwaldo/auth2/pkg/log"
)

// UserService defines the interface for user-related operations
type UserService interface {
	// GetUserEmail retrieves a user's email address by user ID
	GetUserEmail(ctx context.Context, userID string) (string, error)
}

// NotificationConfig defines the configuration for notifications
type NotificationConfig struct {
	// EmailConfig is the configuration for email notifications
	EmailConfig *EmailConfig
	// LogNotifications determines if notifications should be logged
	LogNotifications bool
}

// DefaultNotificationConfig returns a default notification configuration
func DefaultNotificationConfig() *NotificationConfig {
	return &NotificationConfig{
		EmailConfig:      DefaultEmailConfig(),
		LogNotifications: true,
	}
}

// NotificationManager is an implementation of the NotificationService interface
// that can send notifications through multiple channels
type NotificationManager struct {
	// userService is used to retrieve user information
	userService UserService
	// emailSender is used to send email notifications
	emailSender EmailSender
	// config is the notification configuration
	config *NotificationConfig
	// logger is the logger for the notification manager
	logger *slog.Logger
}

// NewNotificationManager creates a new notification manager
func NewNotificationManager(
	userService UserService,
	emailSender EmailSender,
	config *NotificationConfig,
) *NotificationManager {
	if config == nil {
		config = DefaultNotificationConfig()
	}

	return &NotificationManager{
		userService: userService,
		emailSender: emailSender,
		config:      config,
		logger:      log.Default().Logger.With(slog.String("component", "bruteforce.notification")),
	}
}

// NotifyLockout sends a notification about an account lockout
func (m *NotificationManager) NotifyLockout(ctx context.Context, lock *AccountLock) error {
	if lock == nil {
		return fmt.Errorf("lock cannot be nil")
	}

	// Log the notification if configured
	if m.config.LogNotifications {
		m.logger.Info("Account locked notification",
			slog.String("user_id", lock.UserID),
			slog.String("username", lock.Username),
			slog.String("reason", lock.Reason),
			slog.Time("lock_time", lock.LockTime),
			slog.Time("unlock_time", lock.UnlockTime),
			slog.Int("lockout_count", lock.LockoutCount))
	}

	// Skip email notification if no email sender is configured
	if m.emailSender == nil {
		return nil
	}

	// Get the user's email address
	userEmail, err := m.userService.GetUserEmail(ctx, lock.UserID)
	if err != nil {
		m.logger.Error("Failed to get user email for lockout notification",
			slog.String("user_id", lock.UserID),
			slog.String("error", err.Error()))
		return err
	}

	// Format the email body
	body := fmt.Sprintf(
		m.config.EmailConfig.LockoutTemplate,
		lock.Username,
		lock.Reason,
		lock.LockTime.Format("2006-01-02 15:04:05"),
		lock.UnlockTime.Format("2006-01-02 15:04:05"),
	)

	// Send the email
	err = m.emailSender.SendEmail(
		ctx,
		userEmail,
		m.config.EmailConfig.FromAddress,
		m.config.EmailConfig.LockoutSubject,
		body,
	)
	if err != nil {
		m.logger.Error("Failed to send lockout notification email",
			slog.String("user_id", lock.UserID),
			slog.String("username", lock.Username),
			slog.String("email", userEmail),
			slog.String("error", err.Error()))
		return err
	}

	m.logger.Info("Sent lockout notification email",
		slog.String("user_id", lock.UserID),
		slog.String("username", lock.Username),
		slog.String("email", userEmail))

	return nil
}