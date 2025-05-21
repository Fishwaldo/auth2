package bruteforce

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Fishwaldo/auth2/pkg/log"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

const (
	// PluginID is the unique identifier for the bruteforce protection plugin
	PluginID = "auth2.security.bruteforce"
)

// AuthIntegration provides helpers for integrating with auth providers
type AuthIntegration struct {
	manager *ProtectionManager
	logger  *slog.Logger
}

// NewAuthIntegration creates a new authentication integration helper
func NewAuthIntegration(manager *ProtectionManager) *AuthIntegration {
	return &AuthIntegration{
		manager: manager,
		logger:  log.Default().Logger.With(slog.String("component", "bruteforce.auth")),
	}
}

// CheckBeforeAuthentication should be called before authenticating a user
func (i *AuthIntegration) CheckBeforeAuthentication(
	ctx context.Context,
	userID, username, ipAddress, providerID string,
) error {
	status, lock, err := i.manager.CheckAttempt(ctx, userID, username, ipAddress, providerID)
	if err != nil {
		return err
	}

	switch status {
	case StatusLockedOut:
		return AccountLockedError(
			userID,
			lock.Reason,
			lock.UnlockTime.Format(time.RFC3339),
		)
	case StatusRateLimited:
		identifier := username
		if ipAddress != "" {
			identifier = ipAddress
		}
		rateLimit := i.manager.config.MaxAttempts
		timeWindow := i.manager.config.AttemptWindowDuration
		
		// If this is IP-based rate limiting, use those values
		if ipAddress != "" {
			rateLimit = i.manager.config.IPRateLimit
			timeWindow = i.manager.config.IPRateLimitWindow
		}
		
		return RateLimitError(identifier, rateLimit, fmt.Sprintf("%v", timeWindow))
	default:
		return nil
	}
}

// RecordAuthenticationAttempt records an authentication attempt
func (i *AuthIntegration) RecordAuthenticationAttempt(
	ctx context.Context,
	userID, username, ipAddress, providerID string,
	successful bool,
	clientInfo map[string]string,
) error {
	attempt := &LoginAttempt{
		UserID:       userID,
		Username:     username,
		IPAddress:    ipAddress,
		Timestamp:    time.Now(),
		Successful:   successful,
		AuthProvider: providerID,
		ClientInfo:   clientInfo,
	}

	return i.manager.RecordAttempt(ctx, attempt)
}

// GetPluginMetadata returns the metadata for the bruteforce protection plugin
func GetPluginMetadata() metadata.ProviderMetadata {
	return metadata.ProviderMetadata{
		ID:          PluginID,
		Type:        metadata.ProviderTypeSecurity,
		Version:     "1.0.0",
		Name:        "Brute Force Protection",
		Description: "Protects against brute force and credential stuffing attacks",
		Author:      "Auth2 Team",
	}
}