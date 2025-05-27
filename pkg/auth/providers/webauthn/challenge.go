package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

const (
	challengeNamespace = "webauthn_challenges"
	challengeLength    = 32
)

// ChallengeManager manages WebAuthn challenges
type ChallengeManager struct {
	store   metadata.StateStore
	timeout time.Duration
}

// NewChallengeManager creates a new challenge manager
func NewChallengeManager(store metadata.StateStore, timeout time.Duration) *ChallengeManager {
	return &ChallengeManager{
		store:   store,
		timeout: timeout,
	}
}

// CreateChallenge creates a new challenge for a user
func (cm *ChallengeManager) CreateChallenge(ctx context.Context, userID string, challengeType string) (*Challenge, error) {
	// Generate random challenge
	challengeBytes := make([]byte, challengeLength)
	if _, err := rand.Read(challengeBytes); err != nil {
		return nil, WrapError(err, "failed to generate challenge")
	}
	
	// Create challenge object
	challenge := &Challenge{
		ID:        base64.URLEncoding.EncodeToString(challengeBytes),
		UserID:    userID,
		Challenge: challengeBytes,
		Type:      challengeType,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(cm.timeout),
	}
	
	// Store challenge
	if err := cm.store.StoreState(ctx, challengeNamespace, userID, challenge.ID, challenge); err != nil {
		return nil, WrapError(err, "failed to store challenge")
	}
	
	return challenge, nil
}

// ValidateChallenge validates and consumes a challenge
func (cm *ChallengeManager) ValidateChallenge(ctx context.Context, userID string, challengeID string) (*Challenge, error) {
	// Retrieve challenge
	var challenge Challenge
	if err := cm.store.GetState(ctx, challengeNamespace, userID, challengeID, &challenge); err != nil {
		return nil, ErrInvalidChallenge
	}
	
	// Check expiration
	if time.Now().After(challenge.ExpiresAt) {
		// Delete expired challenge
		_ = cm.store.DeleteState(ctx, challengeNamespace, userID, challengeID)
		return nil, ErrInvalidChallenge
	}
	
	// Delete challenge (one-time use)
	if err := cm.store.DeleteState(ctx, challengeNamespace, userID, challengeID); err != nil {
		return nil, WrapError(err, "failed to delete challenge")
	}
	
	return &challenge, nil
}

// CleanupExpiredChallenges removes expired challenges for a user
func (cm *ChallengeManager) CleanupExpiredChallenges(ctx context.Context, userID string) error {
	// List all challenges for the user
	keys, err := cm.store.ListStateKeys(ctx, challengeNamespace, userID)
	if err != nil {
		return WrapError(err, "failed to list challenges")
	}
	
	now := time.Now()
	for _, key := range keys {
		var challenge Challenge
		if err := cm.store.GetState(ctx, challengeNamespace, userID, key, &challenge); err != nil {
			continue // Skip invalid challenges
		}
		
		// Delete if expired
		if now.After(challenge.ExpiresAt) {
			_ = cm.store.DeleteState(ctx, challengeNamespace, userID, key)
		}
	}
	
	return nil
}

// challengeKey generates a storage key for a challenge
func challengeKey(challengeID string) string {
	return fmt.Sprintf("challenge_%s", challengeID)
}