package webauthn

import (
	"time"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Config represents the configuration for the WebAuthn provider
type Config struct {
	// Relying Party settings
	RPDisplayName string   `json:"rp_display_name"`
	RPID          string   `json:"rp_id"`
	RPOrigins     []string `json:"rp_origins"`
	
	// Security preferences
	AttestationPreference   AttestationConveyancePreference `json:"attestation_preference"`
	UserVerification       UserVerificationRequirement      `json:"user_verification"`
	ResidentKeyRequirement ResidentKeyRequirement           `json:"resident_key_requirement"`
	
	// Authenticator preferences
	AuthenticatorAttachment AuthenticatorAttachment `json:"authenticator_attachment,omitempty"`
	RequireResidentKey      bool                    `json:"require_resident_key"`
	
	// Timeouts
	Timeout          time.Duration `json:"timeout"`           // Registration/authentication timeout
	ChallengeTimeout time.Duration `json:"challenge_timeout"` // How long challenges are valid
	
	// Supported algorithms (COSE algorithm identifiers)
	// Default: ES256 (-7), RS256 (-257)
	SupportedAlgorithms []int64 `json:"supported_algorithms,omitempty"`
	
	// StateStore for persistence
	StateStore metadata.StateStore `json:"-"`
	
	// Debug mode
	Debug bool `json:"debug"`
}

// DefaultConfig returns a default WebAuthn configuration
func DefaultConfig() *Config {
	return &Config{
		RPDisplayName:           "Auth2 Application",
		RPID:                    "localhost",
		RPOrigins:               []string{"http://localhost", "https://localhost"},
		AttestationPreference:   AttestationNone,
		UserVerification:        UserVerificationPreferred,
		ResidentKeyRequirement:  ResidentKeyPreferred,
		RequireResidentKey:      false,
		Timeout:                 60 * time.Second,
		ChallengeTimeout:        5 * time.Minute,
		SupportedAlgorithms:     []int64{-7, -257}, // ES256, RS256
		Debug:                   false,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.RPDisplayName == "" {
		return ErrInvalidConfig("rp_display_name is required")
	}
	if c.RPID == "" {
		return ErrInvalidConfig("rp_id is required")
	}
	if len(c.RPOrigins) == 0 {
		return ErrInvalidConfig("at least one rp_origin is required")
	}
	if c.Timeout <= 0 {
		c.Timeout = 60 * time.Second
	}
	if c.ChallengeTimeout <= 0 {
		c.ChallengeTimeout = 5 * time.Minute
	}
	if len(c.SupportedAlgorithms) == 0 {
		c.SupportedAlgorithms = []int64{-7, -257} // ES256, RS256
	}
	if c.StateStore == nil {
		return ErrInvalidConfig("state_store is required")
	}
	return nil
}