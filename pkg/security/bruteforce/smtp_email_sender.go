package bruteforce

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"

	"github.com/Fishwaldo/auth2/pkg/log"
)

// SMTPConfig defines the configuration for the SMTP email sender
type SMTPConfig struct {
	// Host is the SMTP server host
	Host string
	// Port is the SMTP server port
	Port int
	// Username is the SMTP server username
	Username string
	// Password is the SMTP server password
	Password string
	// UseSSL determines if SSL should be used
	UseSSL bool
	// FromAddress is the default from address for emails
	FromAddress string
}

// DefaultSMTPConfig returns a default SMTP configuration
func DefaultSMTPConfig() *SMTPConfig {
	return &SMTPConfig{
		Host:        "smtp.example.com",
		Port:        587,
		Username:    "user@example.com",
		Password:    "password",
		UseSSL:      false,
		FromAddress: "security@example.com",
	}
}

// SMTPEmailSender is an implementation of the EmailSender interface
// that sends emails via SMTP
type SMTPEmailSender struct {
	// config is the SMTP configuration
	config *SMTPConfig
	// logger is the logger for the SMTP email sender
	logger *slog.Logger
}

// NewSMTPEmailSender creates a new SMTP email sender
func NewSMTPEmailSender(config *SMTPConfig) *SMTPEmailSender {
	if config == nil {
		config = DefaultSMTPConfig()
	}

	return &SMTPEmailSender{
		config: config,
		logger: log.Default().Logger.With(slog.String("component", "bruteforce.smtp")),
	}
}

// SendEmail sends an email via SMTP
func (s *SMTPEmailSender) SendEmail(ctx context.Context, to, from, subject, body string) error {
	// If from address is empty, use the default
	if from == "" {
		from = s.config.FromAddress
	}

	// Format the email message
	message := fmt.Sprintf(
		"From: %s\r\n"+
			"To: %s\r\n"+
			"Subject: %s\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			"%s",
		from, to, subject, body,
	)

	// Connect to the SMTP server
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	auth := smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)

	// Send the email
	err := smtp.SendMail(
		addr,
		auth,
		from,
		[]string{to},
		[]byte(message),
	)
	if err != nil {
		s.logger.Error("Failed to send email",
			slog.String("to", to),
			slog.String("from", from),
			slog.String("subject", subject),
			slog.String("error", err.Error()))
		return err
	}

	s.logger.Info("Email sent successfully",
		slog.String("to", to),
		slog.String("from", from),
		slog.String("subject", subject))

	return nil
}

// Validate checks if the SMTP configuration is valid
func (s *SMTPEmailSender) Validate() error {
	if s.config.Host == "" {
		return fmt.Errorf("SMTP host cannot be empty")
	}

	if s.config.Port <= 0 {
		return fmt.Errorf("SMTP port must be positive")
	}

	if s.config.Username == "" {
		return fmt.Errorf("SMTP username cannot be empty")
	}

	if s.config.Password == "" {
		return fmt.Errorf("SMTP password cannot be empty")
	}

	if s.config.FromAddress == "" {
		return fmt.Errorf("SMTP from address cannot be empty")
	}

	if !strings.Contains(s.config.FromAddress, "@") {
		return fmt.Errorf("SMTP from address must be a valid email address")
	}

	return nil
}