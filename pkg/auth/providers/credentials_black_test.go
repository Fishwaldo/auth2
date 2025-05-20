package providers_test

import (
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/stretchr/testify/assert"
)

func TestCredentialTypes(t *testing.T) {
	t.Run("UsernamePasswordCredentials", func(t *testing.T) {
		creds := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		assert.Equal(t, providers.CredentialTypeUsernamePassword, creds.GetType())
		assert.Equal(t, "testuser", creds.Username)
		assert.Equal(t, "testpassword", creds.Password)
	})
	
	t.Run("OAuthCredentials", func(t *testing.T) {
		creds := providers.OAuthCredentials{
			ProviderName: "google",
			Code:         "test-code",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
			Scope:        "email profile",
			TokenType:    "Bearer",
			AccessToken:  "test-access-token",
			RefreshToken: "test-refresh-token",
		}
		
		assert.Equal(t, providers.CredentialTypeOAuth, creds.GetType())
		assert.Equal(t, "google", creds.ProviderName)
		assert.Equal(t, "test-code", creds.Code)
		assert.Equal(t, "https://example.com/callback", creds.RedirectURI)
		assert.Equal(t, "test-state", creds.State)
		assert.Equal(t, "email profile", creds.Scope)
		assert.Equal(t, "Bearer", creds.TokenType)
		assert.Equal(t, "test-access-token", creds.AccessToken)
		assert.Equal(t, "test-refresh-token", creds.RefreshToken)
	})
	
	t.Run("SAMLCredentials", func(t *testing.T) {
		creds := providers.SAMLCredentials{
			SAMLResponse: "test-saml-response",
			RelayState:   "test-relay-state",
		}
		
		assert.Equal(t, providers.CredentialTypeSAML, creds.GetType())
		assert.Equal(t, "test-saml-response", creds.SAMLResponse)
		assert.Equal(t, "test-relay-state", creds.RelayState)
	})
	
	t.Run("WebAuthnCredentials", func(t *testing.T) {
		creds := providers.WebAuthnCredentials{
			CredentialID:      []byte("test-credential-id"),
			AuthenticatorData: []byte("test-authenticator-data"),
			ClientDataJSON:    []byte("test-client-data-json"),
			Signature:         []byte("test-signature"),
			UserHandle:        []byte("test-user-handle"),
			Challenge:         "test-challenge",
			RelyingPartyID:    "example.com",
			UserVerification:  "required",
			Extensions: map[string]interface{}{
				"test-extension": "test-value",
			},
			RegistrationPhase: true,
		}
		
		assert.Equal(t, providers.CredentialTypeWebAuthn, creds.GetType())
		assert.Equal(t, []byte("test-credential-id"), creds.CredentialID)
		assert.Equal(t, []byte("test-authenticator-data"), creds.AuthenticatorData)
		assert.Equal(t, []byte("test-client-data-json"), creds.ClientDataJSON)
		assert.Equal(t, []byte("test-signature"), creds.Signature)
		assert.Equal(t, []byte("test-user-handle"), creds.UserHandle)
		assert.Equal(t, "test-challenge", creds.Challenge)
		assert.Equal(t, "example.com", creds.RelyingPartyID)
		assert.Equal(t, "required", creds.UserVerification)
		assert.Equal(t, "test-value", creds.Extensions["test-extension"])
		assert.True(t, creds.RegistrationPhase)
	})
	
	t.Run("MFACredentials", func(t *testing.T) {
		creds := providers.MFACredentials{
			UserID:     "test-user-id",
			ProviderID: "totp",
			Code:       "123456",
			Challenge:  "test-challenge",
		}
		
		assert.Equal(t, providers.CredentialTypeMFA, creds.GetType())
		assert.Equal(t, "test-user-id", creds.UserID)
		assert.Equal(t, "totp", creds.ProviderID)
		assert.Equal(t, "123456", creds.Code)
		assert.Equal(t, "test-challenge", creds.Challenge)
	})
	
	t.Run("SessionCredentials", func(t *testing.T) {
		creds := providers.SessionCredentials{
			SessionID: "test-session-id",
			Token:     "test-token",
		}
		
		assert.Equal(t, providers.CredentialTypeSession, creds.GetType())
		assert.Equal(t, "test-session-id", creds.SessionID)
		assert.Equal(t, "test-token", creds.Token)
	})
	
	t.Run("TokenCredentials", func(t *testing.T) {
		creds := providers.TokenCredentials{
			TokenType:  "Bearer",
			TokenValue: "test-token-value",
		}
		
		assert.Equal(t, providers.CredentialTypeToken, creds.GetType())
		assert.Equal(t, "Bearer", creds.TokenType)
		assert.Equal(t, "test-token-value", creds.TokenValue)
	})
}