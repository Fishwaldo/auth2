package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// StateManager handles OAuth2 state parameter management for CSRF protection
type StateManager struct {
	store    metadata.StateStore
	ttl      time.Duration
	provider string
}

// NewStateManager creates a new state manager
func NewStateManager(store metadata.StateStore, ttl time.Duration, provider string) *StateManager {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &StateManager{
		store:    store,
		ttl:      ttl,
		provider: provider,
	}
}

// CreateState generates and stores a new state parameter
func (sm *StateManager) CreateState(ctx context.Context, redirectURI string, extra map[string]string) (string, error) {
	// Generate random state
	state, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	
	// Create state data
	now := time.Now()
	stateData := &StateData{
		State:       state,
		RedirectURI: redirectURI,
		CreatedAt:   now,
		ExpiresAt:   now.Add(sm.ttl),
		Extra:       extra,
	}
	
	// Store state data
	if err := sm.store.StoreState(ctx, "oauth2_state", sm.provider, state, stateData); err != nil {
		return "", fmt.Errorf("failed to store state: %w", err)
	}
	
	return state, nil
}

// ValidateState validates and consumes a state parameter
func (sm *StateManager) ValidateState(ctx context.Context, state string) (*StateData, error) {
	if state == "" {
		return nil, ErrInvalidState
	}
	
	// Retrieve state data
	var stateData StateData
	err := sm.store.GetState(ctx, "oauth2_state", sm.provider, state, &stateData)
	if err != nil {
		return nil, ErrStateNotFound
	}
	
	// Check expiration
	if time.Now().After(stateData.ExpiresAt) {
		// Delete expired state
		_ = sm.store.DeleteState(ctx, "oauth2_state", sm.provider, state)
		return nil, ErrStateExpired
	}
	
	// Delete state after successful validation (one-time use)
	if err := sm.store.DeleteState(ctx, "oauth2_state", sm.provider, state); err != nil {
		// Log but don't fail - state was valid
		// In production, this should be logged
	}
	
	return &stateData, nil
}

// CleanupExpiredStates removes expired state entries
func (sm *StateManager) CleanupExpiredStates(ctx context.Context) error {
	// List all state keys for this provider
	keys, err := sm.store.ListStateKeys(ctx, "oauth2_state", sm.provider)
	if err != nil {
		return fmt.Errorf("failed to list state keys: %w", err)
	}
	
	now := time.Now()
	for _, key := range keys {
		var stateData StateData
		err := sm.store.GetState(ctx, "oauth2_state", sm.provider, key, &stateData)
		if err != nil {
			continue // Skip if we can't read it
		}
		
		if now.After(stateData.ExpiresAt) {
			_ = sm.store.DeleteState(ctx, "oauth2_state", sm.provider, key)
		}
	}
	
	return nil
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}