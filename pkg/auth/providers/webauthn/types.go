package webauthn

import (
	"time"
)

// AttestationConveyancePreference represents the attestation preference
type AttestationConveyancePreference string

const (
	// AttestationNone indicates no attestation is required
	AttestationNone AttestationConveyancePreference = "none"
	// AttestationIndirect indicates indirect attestation is preferred
	AttestationIndirect AttestationConveyancePreference = "indirect"
	// AttestationDirect indicates direct attestation is preferred
	AttestationDirect AttestationConveyancePreference = "direct"
	// AttestationEnterprise indicates enterprise attestation is preferred
	AttestationEnterprise AttestationConveyancePreference = "enterprise"
)

// UserVerificationRequirement represents the user verification requirement
type UserVerificationRequirement string

const (
	// UserVerificationRequired requires user verification
	UserVerificationRequired UserVerificationRequirement = "required"
	// UserVerificationPreferred prefers user verification but doesn't require it
	UserVerificationPreferred UserVerificationRequirement = "preferred"
	// UserVerificationDiscouraged discourages user verification
	UserVerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// ResidentKeyRequirement represents the resident key requirement
type ResidentKeyRequirement string

const (
	// ResidentKeyDiscouraged discourages resident keys
	ResidentKeyDiscouraged ResidentKeyRequirement = "discouraged"
	// ResidentKeyPreferred prefers resident keys
	ResidentKeyPreferred ResidentKeyRequirement = "preferred"
	// ResidentKeyRequired requires resident keys
	ResidentKeyRequired ResidentKeyRequirement = "required"
)

// AuthenticatorAttachment represents the authenticator attachment
type AuthenticatorAttachment string

const (
	// AttachmentPlatform indicates a platform authenticator
	AttachmentPlatform AuthenticatorAttachment = "platform"
	// AttachmentCrossPlatform indicates a cross-platform authenticator
	AttachmentCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Challenge represents a WebAuthn challenge
type Challenge struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Challenge []byte    `json:"challenge"`
	Type      string    `json:"type"` // "registration" or "authentication"
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Credential represents a stored WebAuthn credential
type Credential struct {
	ID              []byte                  `json:"id"`
	PublicKey       []byte                  `json:"public_key"`
	AttestationType string                  `json:"attestation_type"`
	Transport       []string                `json:"transport"`
	Flags           CredentialFlags         `json:"flags"`
	Authenticator   AuthenticatorData       `json:"authenticator"`
	CreatedAt       time.Time               `json:"created_at"`
	LastUsedAt      time.Time               `json:"last_used_at"`
	Counter         uint32                  `json:"counter"`
	BackupEligible  bool                    `json:"backup_eligible"`
	BackupState     bool                    `json:"backup_state"`
	Attachment      AuthenticatorAttachment `json:"attachment,omitempty"`
}

// CredentialFlags represents credential flags
type CredentialFlags struct {
	UserPresent    bool `json:"user_present"`
	UserVerified   bool `json:"user_verified"`
	BackupEligible bool `json:"backup_eligible"`
	BackupState    bool `json:"backup_state"`
}

// AuthenticatorData represents authenticator data
type AuthenticatorData struct {
	AAGUID       []byte `json:"aaguid"`
	SignCount    uint32 `json:"sign_count"`
	CloneWarning bool   `json:"clone_warning"`
}

// UserCredentials represents all credentials for a user
type UserCredentials struct {
	UserID      string       `json:"user_id"`
	Credentials []Credential `json:"credentials"`
}

// RegistrationOptions represents options for credential creation
type RegistrationOptions struct {
	Challenge                []byte                          `json:"challenge"`
	RelyingParty             RelyingParty                    `json:"rp"`
	User                     User                            `json:"user"`
	PubKeyCredParams         []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	Timeout                  uint64                          `json:"timeout,omitempty"`
	ExcludeCredentials       []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
	AuthenticatorSelection   *AuthenticatorSelection         `json:"authenticatorSelection,omitempty"`
	Attestation              AttestationConveyancePreference `json:"attestation,omitempty"`
	Extensions               map[string]interface{}          `json:"extensions,omitempty"`
}

// AuthenticationOptions represents options for authentication
type AuthenticationOptions struct {
	Challenge          []byte                          `json:"challenge"`
	Timeout            uint64                          `json:"timeout,omitempty"`
	RelyingPartyID     string                          `json:"rpId,omitempty"`
	AllowCredentials   []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification   UserVerificationRequirement     `json:"userVerification,omitempty"`
	Extensions         map[string]interface{}          `json:"extensions,omitempty"`
}

// RelyingParty represents the relying party
type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// User represents a WebAuthn user
type User struct {
	ID          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PublicKeyCredentialParameters represents credential parameters
type PublicKeyCredentialParameters struct {
	Type      string `json:"type"`
	Algorithm int64  `json:"alg"`
}

// PublicKeyCredentialDescriptor describes a credential
type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         []byte   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// AuthenticatorSelection represents authenticator selection criteria
type AuthenticatorSelection struct {
	AuthenticatorAttachment AuthenticatorAttachment     `json:"authenticatorAttachment,omitempty"`
	ResidentKey             ResidentKeyRequirement      `json:"residentKey,omitempty"`
	RequireResidentKey      bool                        `json:"requireResidentKey,omitempty"`
	UserVerification        UserVerificationRequirement `json:"userVerification,omitempty"`
}

// RegistrationResponse represents the response from credential creation
type RegistrationResponse struct {
	ID                     string                           `json:"id"`
	RawID                  []byte                           `json:"rawId"`
	Type                   string                           `json:"type"`
	AttestationObject      []byte                           `json:"attestationObject"`
	ClientDataJSON         []byte                           `json:"clientDataJSON"`
	Transports             []string                         `json:"transports,omitempty"`
	PublicKeyAlgorithm     int64                            `json:"publicKeyAlgorithm,omitempty"`
	PublicKey              []byte                           `json:"publicKey,omitempty"`
	AuthenticatorAttachment AuthenticatorAttachment         `json:"authenticatorAttachment,omitempty"`
}

// AuthenticationResponse represents the response from authentication
type AuthenticationResponse struct {
	ID                 string `json:"id"`
	RawID              []byte `json:"rawId"`
	Type               string `json:"type"`
	AuthenticatorData  []byte `json:"authenticatorData"`
	ClientDataJSON     []byte `json:"clientDataJSON"`
	Signature          []byte `json:"signature"`
	UserHandle         []byte `json:"userHandle,omitempty"`
}