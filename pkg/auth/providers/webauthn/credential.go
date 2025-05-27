package webauthn

import (
	"context"
	"fmt"
	"time"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

const (
	credentialNamespace = "webauthn_credentials"
)

// CredentialStore manages WebAuthn credentials
type CredentialStore struct {
	store metadata.StateStore
}

// NewCredentialStore creates a new credential store
func NewCredentialStore(store metadata.StateStore) *CredentialStore {
	return &CredentialStore{
		store: store,
	}
}

// GetUserCredentials retrieves all credentials for a user
func (cs *CredentialStore) GetUserCredentials(ctx context.Context, userID string) (*UserCredentials, error) {
	var userCreds UserCredentials
	err := cs.store.GetState(ctx, credentialNamespace, userID, "credentials", &userCreds)
	if err != nil {
		// If not found, return empty credentials
		return &UserCredentials{
			UserID:      userID,
			Credentials: []Credential{},
		}, nil
	}
	return &userCreds, nil
}

// AddCredential adds a new credential for a user
func (cs *CredentialStore) AddCredential(ctx context.Context, userID string, credential *Credential) error {
	// Get existing credentials
	userCreds, err := cs.GetUserCredentials(ctx, userID)
	if err != nil {
		return WrapError(err, "failed to get user credentials")
	}
	
	// Check for duplicate
	for _, existing := range userCreds.Credentials {
		if string(existing.ID) == string(credential.ID) {
			return ErrDuplicateCredential
		}
	}
	
	// Add new credential
	credential.CreatedAt = time.Now()
	credential.LastUsedAt = time.Now()
	userCreds.Credentials = append(userCreds.Credentials, *credential)
	
	// Store updated credentials
	if err := cs.store.StoreState(ctx, credentialNamespace, userID, "credentials", userCreds); err != nil {
		return WrapError(err, "failed to store credentials")
	}
	
	return nil
}

// GetCredential retrieves a specific credential
func (cs *CredentialStore) GetCredential(ctx context.Context, userID string, credentialID []byte) (*Credential, error) {
	userCreds, err := cs.GetUserCredentials(ctx, userID)
	if err != nil {
		return nil, err
	}
	
	for i := range userCreds.Credentials {
		if string(userCreds.Credentials[i].ID) == string(credentialID) {
			return &userCreds.Credentials[i], nil
		}
	}
	
	return nil, ErrCredentialNotFound
}

// UpdateCredential updates an existing credential
func (cs *CredentialStore) UpdateCredential(ctx context.Context, userID string, credential *Credential) error {
	userCreds, err := cs.GetUserCredentials(ctx, userID)
	if err != nil {
		return WrapError(err, "failed to get user credentials")
	}
	
	found := false
	for i := range userCreds.Credentials {
		if string(userCreds.Credentials[i].ID) == string(credential.ID) {
			credential.LastUsedAt = time.Now()
			userCreds.Credentials[i] = *credential
			found = true
			break
		}
	}
	
	if !found {
		return ErrCredentialNotFound
	}
	
	// Store updated credentials
	if err := cs.store.StoreState(ctx, credentialNamespace, userID, "credentials", userCreds); err != nil {
		return WrapError(err, "failed to update credentials")
	}
	
	return nil
}

// RemoveCredential removes a credential from a user
func (cs *CredentialStore) RemoveCredential(ctx context.Context, userID string, credentialID []byte) error {
	userCreds, err := cs.GetUserCredentials(ctx, userID)
	if err != nil {
		return WrapError(err, "failed to get user credentials")
	}
	
	// Filter out the credential to remove
	filtered := make([]Credential, 0, len(userCreds.Credentials))
	found := false
	for _, cred := range userCreds.Credentials {
		if string(cred.ID) != string(credentialID) {
			filtered = append(filtered, cred)
		} else {
			found = true
		}
	}
	
	if !found {
		return ErrCredentialNotFound
	}
	
	userCreds.Credentials = filtered
	
	// Store updated credentials
	if err := cs.store.StoreState(ctx, credentialNamespace, userID, "credentials", userCreds); err != nil {
		return WrapError(err, "failed to update credentials")
	}
	
	return nil
}

// ListAllCredentials lists all credentials for all users (admin function)
func (cs *CredentialStore) ListAllCredentials(ctx context.Context) (map[string]*UserCredentials, error) {
	// This would need to be implemented based on the specific StateStore implementation
	// For now, return an error indicating it's not supported
	return nil, fmt.Errorf("listing all credentials is not supported")
}

// HasCredentials checks if a user has any credentials
func (cs *CredentialStore) HasCredentials(ctx context.Context, userID string) (bool, error) {
	userCreds, err := cs.GetUserCredentials(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(userCreds.Credentials) > 0, nil
}