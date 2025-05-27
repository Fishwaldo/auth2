package webauthn_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCredentialStore_GetUserCredentials(t *testing.T) {
	mockStore := &mockStateStore{}
	credStore := webauthn.NewCredentialStore(mockStore)
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("existing credentials", func(t *testing.T) {
		// Setup test data
		testCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *testCreds
		}).Return(nil).Once()
		
		// Call GetUserCredentials
		result, err := credStore.GetUserCredentials(ctx, userID)
		
		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, userID, result.UserID)
		assert.Len(t, result.Credentials, 1)
		assert.Equal(t, []byte("cred1"), result.Credentials[0].ID)
		
		mockStore.AssertExpectations(t)
	})
	
	t.Run("no credentials", func(t *testing.T) {
		// Setup mock expectations - return error (not found)
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Return(assert.AnError).Once()
		
		// Call GetUserCredentials
		result, err := credStore.GetUserCredentials(ctx, userID)
		
		// Should return empty credentials, not error
		assert.NoError(t, err)
		assert.Equal(t, userID, result.UserID)
		assert.Len(t, result.Credentials, 0)
		
		mockStore.AssertExpectations(t)
	})
}

func TestCredentialStore_AddCredential(t *testing.T) {
	mockStore := &mockStateStore{}
	credStore := webauthn.NewCredentialStore(mockStore)
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("add first credential", func(t *testing.T) {
		newCred := &webauthn.Credential{
			ID:        []byte("new-cred"),
			PublicKey: []byte("new-pubkey"),
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Return(assert.AnError).Once()
		
		mockStore.On("StoreState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			stored := args.Get(4).(*webauthn.UserCredentials)
			assert.Equal(t, userID, stored.UserID)
			assert.Len(t, stored.Credentials, 1)
			assert.Equal(t, newCred.ID, stored.Credentials[0].ID)
			assert.NotZero(t, stored.Credentials[0].CreatedAt)
			assert.NotZero(t, stored.Credentials[0].LastUsedAt)
		}).Return(nil).Once()
		
		// Call AddCredential
		err := credStore.AddCredential(ctx, userID, newCred)
		
		// Assertions
		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})
	
	t.Run("add additional credential", func(t *testing.T) {
		existingCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("existing-cred"),
					PublicKey: []byte("existing-pubkey"),
				},
			},
		}
		
		newCred := &webauthn.Credential{
			ID:        []byte("new-cred"),
			PublicKey: []byte("new-pubkey"),
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *existingCreds
		}).Return(nil).Once()
		
		mockStore.On("StoreState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			stored := args.Get(4).(*webauthn.UserCredentials)
			assert.Equal(t, userID, stored.UserID)
			assert.Len(t, stored.Credentials, 2)
			assert.Equal(t, []byte("existing-cred"), stored.Credentials[0].ID)
			assert.Equal(t, newCred.ID, stored.Credentials[1].ID)
		}).Return(nil).Once()
		
		// Call AddCredential
		err := credStore.AddCredential(ctx, userID, newCred)
		
		// Assertions
		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})
	
	t.Run("duplicate credential", func(t *testing.T) {
		existingCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("existing-cred"),
					PublicKey: []byte("existing-pubkey"),
				},
			},
		}
		
		duplicateCred := &webauthn.Credential{
			ID:        []byte("existing-cred"), // Same ID
			PublicKey: []byte("different-pubkey"),
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *existingCreds
		}).Return(nil).Once()
		
		// Call AddCredential
		err := credStore.AddCredential(ctx, userID, duplicateCred)
		
		// Should fail with duplicate error
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrDuplicateCredential, err)
		mockStore.AssertExpectations(t)
	})
}

func TestCredentialStore_GetCredential(t *testing.T) {
	mockStore := &mockStateStore{}
	credStore := webauthn.NewCredentialStore(mockStore)
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("credential exists", func(t *testing.T) {
		testCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
				{
					ID:        []byte("cred2"),
					PublicKey: []byte("pubkey2"),
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *testCreds
		}).Return(nil).Once()
		
		// Call GetCredential
		result, err := credStore.GetCredential(ctx, userID, []byte("cred2"))
		
		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, []byte("cred2"), result.ID)
		assert.Equal(t, []byte("pubkey2"), result.PublicKey)
		
		mockStore.AssertExpectations(t)
	})
	
	t.Run("credential not found", func(t *testing.T) {
		testCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *testCreds
		}).Return(nil).Once()
		
		// Call GetCredential
		result, err := credStore.GetCredential(ctx, userID, []byte("nonexistent"))
		
		// Should fail with not found error
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrCredentialNotFound, err)
		assert.Nil(t, result)
		
		mockStore.AssertExpectations(t)
	})
}

func TestCredentialStore_UpdateCredential(t *testing.T) {
	mockStore := &mockStateStore{}
	credStore := webauthn.NewCredentialStore(mockStore)
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("update existing credential", func(t *testing.T) {
		existingCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
					Counter:   10,
				},
			},
		}
		
		updatedCred := &webauthn.Credential{
			ID:        []byte("cred1"),
			PublicKey: []byte("pubkey1"),
			Counter:   11, // Updated counter
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *existingCreds
		}).Return(nil).Once()
		
		mockStore.On("StoreState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			stored := args.Get(4).(*webauthn.UserCredentials)
			assert.Equal(t, userID, stored.UserID)
			assert.Len(t, stored.Credentials, 1)
			assert.Equal(t, uint32(11), stored.Credentials[0].Counter)
			assert.NotZero(t, stored.Credentials[0].LastUsedAt)
		}).Return(nil).Once()
		
		// Call UpdateCredential
		err := credStore.UpdateCredential(ctx, userID, updatedCred)
		
		// Assertions
		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})
	
	t.Run("update nonexistent credential", func(t *testing.T) {
		existingCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
			},
		}
		
		nonexistentCred := &webauthn.Credential{
			ID:        []byte("nonexistent"),
			PublicKey: []byte("pubkey"),
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *existingCreds
		}).Return(nil).Once()
		
		// Call UpdateCredential
		err := credStore.UpdateCredential(ctx, userID, nonexistentCred)
		
		// Should fail with not found error
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrCredentialNotFound, err)
		mockStore.AssertExpectations(t)
	})
}

func TestCredentialStore_RemoveCredential(t *testing.T) {
	mockStore := &mockStateStore{}
	credStore := webauthn.NewCredentialStore(mockStore)
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("remove existing credential", func(t *testing.T) {
		existingCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
				{
					ID:        []byte("cred2"),
					PublicKey: []byte("pubkey2"),
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *existingCreds
		}).Return(nil).Once()
		
		mockStore.On("StoreState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			stored := args.Get(4).(*webauthn.UserCredentials)
			assert.Equal(t, userID, stored.UserID)
			assert.Len(t, stored.Credentials, 1)
			assert.Equal(t, []byte("cred2"), stored.Credentials[0].ID)
		}).Return(nil).Once()
		
		// Call RemoveCredential
		err := credStore.RemoveCredential(ctx, userID, []byte("cred1"))
		
		// Assertions
		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})
	
	t.Run("remove nonexistent credential", func(t *testing.T) {
		existingCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *existingCreds
		}).Return(nil).Once()
		
		// Call RemoveCredential
		err := credStore.RemoveCredential(ctx, userID, []byte("nonexistent"))
		
		// Should fail with not found error
		assert.Error(t, err)
		assert.Equal(t, webauthn.ErrCredentialNotFound, err)
		mockStore.AssertExpectations(t)
	})
}

func TestCredentialStore_HasCredentials(t *testing.T) {
	mockStore := &mockStateStore{}
	credStore := webauthn.NewCredentialStore(mockStore)
	ctx := context.Background()
	userID := "test-user"
	
	t.Run("user has credentials", func(t *testing.T) {
		testCreds := &webauthn.UserCredentials{
			UserID: userID,
			Credentials: []webauthn.Credential{
				{
					ID:        []byte("cred1"),
					PublicKey: []byte("pubkey1"),
				},
			},
		}
		
		// Setup mock expectations
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Run(func(args mock.Arguments) {
			userCreds := args.Get(4).(*webauthn.UserCredentials)
			*userCreds = *testCreds
		}).Return(nil).Once()
		
		// Call HasCredentials
		result, err := credStore.HasCredentials(ctx, userID)
		
		// Assertions
		assert.NoError(t, err)
		assert.True(t, result)
		mockStore.AssertExpectations(t)
	})
	
	t.Run("user has no credentials", func(t *testing.T) {
		// Setup mock expectations - return error (not found)
		mockStore.On("GetState", ctx, "webauthn_credentials", userID, "credentials", mock.AnythingOfType("*webauthn.UserCredentials")).Return(assert.AnError).Once()
		
		// Call HasCredentials
		result, err := credStore.HasCredentials(ctx, userID)
		
		// Assertions
		assert.NoError(t, err)
		assert.False(t, result)
		mockStore.AssertExpectations(t)
	})
}