package webauthn_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestChallengeManager_CreateChallenge(t *testing.T) {
	mockStore := &mockStateStore{}
	timeout := 5 * time.Minute
	cm := webauthn.NewChallengeManager(mockStore, timeout)
	ctx := context.Background()
	userID := "test-user"
	
	// Setup mock expectations
	mockStore.On("StoreState", ctx, "webauthn_challenges", userID, mock.AnythingOfType("string"), mock.AnythingOfType("*webauthn.Challenge")).Run(func(args mock.Arguments) {
		challengeID := args.Get(3).(string)
		challenge := args.Get(4).(*webauthn.Challenge)
		
		// Verify challenge properties
		assert.Equal(t, challengeID, challenge.ID)
		assert.Equal(t, userID, challenge.UserID)
		assert.Equal(t, "registration", challenge.Type)
		assert.Len(t, challenge.Challenge, 32)
		assert.NotZero(t, challenge.CreatedAt)
		assert.NotZero(t, challenge.ExpiresAt)
		assert.True(t, challenge.ExpiresAt.After(challenge.CreatedAt))
		// Check timeout is approximately correct (within 1 second)
		actualTimeout := challenge.ExpiresAt.Sub(challenge.CreatedAt)
		assert.InDelta(t, timeout.Seconds(), actualTimeout.Seconds(), 1.0)
	}).Return(nil).Once()
	
	// Call CreateChallenge
	challenge, err := cm.CreateChallenge(ctx, userID, "registration")
	
	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, challenge)
	assert.NotEmpty(t, challenge.ID)
	assert.Equal(t, userID, challenge.UserID)
	assert.Equal(t, "registration", challenge.Type)
	assert.Len(t, challenge.Challenge, 32)
	
	// Verify ID is base64 encoded
	_, err = base64.URLEncoding.DecodeString(challenge.ID)
	assert.NoError(t, err)
	
	mockStore.AssertExpectations(t)
}

func TestChallengeManager_ValidateChallenge(t *testing.T) {
	mockStore := &mockStateStore{}
	timeout := 5 * time.Minute
	cm := webauthn.NewChallengeManager(mockStore, timeout)
	ctx := context.Background()
	userID := "test-user"
	challengeID := "test-challenge-id"
	
	t.Run("valid challenge", func(t *testing.T) {
		validChallenge := &webauthn.Challenge{
			ID:        challengeID,
			UserID:    userID,
			Challenge: []byte("test-challenge"),
			Type:      "authentication",
			CreatedAt: time.Now().Add(-1 * time.Minute),
			ExpiresAt: time.Now().Add(4 * time.Minute),
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_challenges", userID, challengeID, mock.AnythingOfType("*webauthn.Challenge")).Run(func(args mock.Arguments) {
			challenge := args.Get(4).(*webauthn.Challenge)
			*challenge = *validChallenge
		}).Return(nil).Once()
		
		mockStore.On("DeleteState", ctx, "webauthn_challenges", userID, challengeID).Return(nil).Once()
		
		// Call ValidateChallenge
		result, err := cm.ValidateChallenge(ctx, userID, challengeID)
		
		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, validChallenge.ID, result.ID)
		assert.Equal(t, validChallenge.UserID, result.UserID)
		assert.Equal(t, validChallenge.Challenge, result.Challenge)
		
		mockStore.AssertExpectations(t)
	})
	
	t.Run("expired challenge", func(t *testing.T) {
		expiredChallenge := &webauthn.Challenge{
			ID:        challengeID,
			UserID:    userID,
			Challenge: []byte("test-challenge"),
			Type:      "authentication",
			CreatedAt: time.Now().Add(-10 * time.Minute),
			ExpiresAt: time.Now().Add(-5 * time.Minute), // Expired
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_challenges", userID, challengeID, mock.AnythingOfType("*webauthn.Challenge")).Run(func(args mock.Arguments) {
			challenge := args.Get(4).(*webauthn.Challenge)
			*challenge = *expiredChallenge
		}).Return(nil).Once()
		
		// Should try to delete expired challenge
		mockStore.On("DeleteState", ctx, "webauthn_challenges", userID, challengeID).Return(nil).Once()
		
		// Call ValidateChallenge
		result, err := cm.ValidateChallenge(ctx, userID, challengeID)
		
		// Should fail with invalid challenge error
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrInvalidChallenge, err)
		assert.Nil(t, result)
		
		mockStore.AssertExpectations(t)
	})
	
	t.Run("challenge not found", func(t *testing.T) {
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_challenges", userID, challengeID, mock.AnythingOfType("*webauthn.Challenge")).Return(assert.AnError).Once()
		
		// Call ValidateChallenge
		result, err := cm.ValidateChallenge(ctx, userID, challengeID)
		
		// Should fail with invalid challenge error
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrInvalidChallenge, err)
		assert.Nil(t, result)
		
		mockStore.AssertExpectations(t)
	})
	
	t.Run("delete fails", func(t *testing.T) {
		validChallenge := &webauthn.Challenge{
			ID:        challengeID,
			UserID:    userID,
			Challenge: []byte("test-challenge"),
			Type:      "authentication",
			CreatedAt: time.Now().Add(-1 * time.Minute),
			ExpiresAt: time.Now().Add(4 * time.Minute),
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_challenges", userID, challengeID, mock.AnythingOfType("*webauthn.Challenge")).Run(func(args mock.Arguments) {
			challenge := args.Get(4).(*webauthn.Challenge)
			*challenge = *validChallenge
		}).Return(nil).Once()
		
		mockStore.On("DeleteState", ctx, "webauthn_challenges", userID, challengeID).Return(assert.AnError).Once()
		
		// Call ValidateChallenge
		result, err := cm.ValidateChallenge(ctx, userID, challengeID)
		
		// Should fail with wrapped error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to delete challenge")
		assert.Nil(t, result)
		
		mockStore.AssertExpectations(t)
	})
}

func TestChallengeManager_CleanupExpiredChallenges(t *testing.T) {
	mockStore := &mockStateStore{}
	timeout := 5 * time.Minute
	cm := webauthn.NewChallengeManager(mockStore, timeout)
	ctx := context.Background()
	userID := "test-user"
	
	// Setup test data
	challenges := []struct {
		id      string
		expired bool
	}{
		{"challenge1", false},
		{"challenge2", true},
		{"challenge3", false},
		{"challenge4", true},
	}
	
	challengeKeys := make([]string, len(challenges))
	for i, c := range challenges {
		challengeKeys[i] = c.id
	}
	
	// Setup mock expectations
	mockStore.On("ListStateKeys", ctx, "webauthn_challenges", userID).Return(challengeKeys, nil).Once()
	
	// Setup expectations for each challenge
	for _, c := range challenges {
		challenge := &webauthn.Challenge{
			ID:        c.id,
			UserID:    userID,
			Challenge: []byte("test-challenge"),
			Type:      "authentication",
		}
		
		if c.expired {
			challenge.CreatedAt = time.Now().Add(-10 * time.Minute)
			challenge.ExpiresAt = time.Now().Add(-5 * time.Minute)
		} else {
			challenge.CreatedAt = time.Now().Add(-1 * time.Minute)
			challenge.ExpiresAt = time.Now().Add(4 * time.Minute)
		}
		
		mockStore.On("GetState", ctx, "webauthn_challenges", userID, c.id, mock.AnythingOfType("*webauthn.Challenge")).Run(func(args mock.Arguments) {
			ch := args.Get(4).(*webauthn.Challenge)
			*ch = *challenge
		}).Return(nil).Once()
		
		// Only expired challenges should be deleted
		if c.expired {
			mockStore.On("DeleteState", ctx, "webauthn_challenges", userID, c.id).Return(nil).Once()
		}
	}
	
	// Call CleanupExpiredChallenges
	err := cm.CleanupExpiredChallenges(ctx, userID)
	
	// Assertions
	assert.NoError(t, err)
	mockStore.AssertExpectations(t)
}

func TestChallengeManager_CleanupExpiredChallenges_ListError(t *testing.T) {
	mockStore := &mockStateStore{}
	timeout := 5 * time.Minute
	cm := webauthn.NewChallengeManager(mockStore, timeout)
	ctx := context.Background()
	userID := "test-user"
	
	// Setup mock expectations - list fails
	mockStore.On("ListStateKeys", ctx, "webauthn_challenges", userID).Return([]string{}, assert.AnError).Once()
	
	// Call CleanupExpiredChallenges
	err := cm.CleanupExpiredChallenges(ctx, userID)
	
	// Should fail with wrapped error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list challenges")
	mockStore.AssertExpectations(t)
}