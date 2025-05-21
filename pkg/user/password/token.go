package password

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// TokenStore defines the interface for token storage and validation
type TokenStore interface {
	// StoreToken stores a token for a user
	StoreToken(ctx context.Context, userID, tokenType, token string, expiry time.Duration) error
	
	// ValidateToken checks if a token is valid for a user
	ValidateToken(ctx context.Context, userID, tokenType, token string) (bool, error)
	
	// RevokeToken marks a token as revoked
	RevokeToken(ctx context.Context, userID, token string) error
	
	// RevokeAllTokensForUser marks all tokens for a user as revoked
	RevokeAllTokensForUser(ctx context.Context, userID string) error
}

// SetTokenStore sets the token store for the password utilities
func (u *Utils) SetTokenStore(store TokenStore) {
	u.tokenStore = store
}

// GenerateToken generates a secure random token
func (u *Utils) generateToken(length int) (string, error) {
	if length < 16 {
		length = 16 // Minimum token length for security
	}
	
	// Generate random bytes
	tokenBytes := make([]byte, length)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	
	// Encode as base64
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

// GeneratePasswordResetToken generates a password reset token for a user
func (u *Utils) GeneratePasswordResetToken(ctx context.Context, userID string, expiry time.Duration) (string, error) {
	if u.tokenStore == nil {
		return "", fmt.Errorf("token store not configured")
	}
	
	// Generate a secure token
	token, err := u.generateToken(32)
	if err != nil {
		return "", err
	}
	
	// Store the token
	err = u.tokenStore.StoreToken(ctx, userID, "password_reset", token, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to store password reset token: %w", err)
	}
	
	return token, nil
}

// ValidatePasswordResetToken validates a password reset token for a user
func (u *Utils) ValidatePasswordResetToken(ctx context.Context, userID, token string) (bool, error) {
	if u.tokenStore == nil {
		return false, fmt.Errorf("token store not configured")
	}
	
	return u.tokenStore.ValidateToken(ctx, userID, "password_reset", token)
}

// RevokePasswordResetToken revokes a password reset token for a user
func (u *Utils) RevokePasswordResetToken(ctx context.Context, userID, token string) error {
	if u.tokenStore == nil {
		return fmt.Errorf("token store not configured")
	}
	
	return u.tokenStore.RevokeToken(ctx, userID, token)
}

// GenerateEmailVerificationToken generates an email verification token for a user
func (u *Utils) GenerateEmailVerificationToken(ctx context.Context, userID string, expiry time.Duration) (string, error) {
	if u.tokenStore == nil {
		return "", fmt.Errorf("token store not configured")
	}
	
	// Generate a secure token
	token, err := u.generateToken(32)
	if err != nil {
		return "", err
	}
	
	// Store the token
	err = u.tokenStore.StoreToken(ctx, userID, "email_verification", token, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to store email verification token: %w", err)
	}
	
	return token, nil
}

// ValidateEmailVerificationToken validates an email verification token for a user
func (u *Utils) ValidateEmailVerificationToken(ctx context.Context, userID, token string) (bool, error) {
	if u.tokenStore == nil {
		return false, fmt.Errorf("token store not configured")
	}
	
	return u.tokenStore.ValidateToken(ctx, userID, "email_verification", token)
}

// RevokeAllTokensForUser revokes all tokens for a user
func (u *Utils) RevokeAllTokensForUser(ctx context.Context, userID string) error {
	if u.tokenStore == nil {
		return fmt.Errorf("token store not configured")
	}
	
	return u.tokenStore.RevokeAllTokensForUser(ctx, userID)
}