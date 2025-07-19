package smartid

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// CallbackURLValidator provides utilities for validating callback URL parameters in DeviceLink authentication flows
type CallbackURLValidator struct {
	entity *CallbackValidationEntity
	result *AuthResult
}

// NewCallbackURLValidator creates a new CallbackURLValidator instance
func NewCallbackURLValidator(entity *CallbackValidationEntity) *CallbackURLValidator {
	return &CallbackURLValidator{
		entity: entity,
		result: NewAuthResult(),
	}
}

// Validate runs all validation checks on the callback URL parameters
func (v *CallbackURLValidator) Validate() *CallbackURLValidator {
	v.validateSessionStatus()
	v.validateSessionSecretDigest()
	v.validateUserChallengeVerifier()
	return v
}

// GetResult returns the validation result
func (v *CallbackURLValidator) GetResult() *AuthResult {
	return v.result
}

// validateSessionStatus checks if the session completed successfully and required fields are present
func (v *CallbackURLValidator) validateSessionStatus() {
	response := v.entity.AuthenticationResponse

	if response.State != "COMPLETE" {
		v.result.AddError("Session is not complete.")
	}

	if response.Result == nil || response.Result.EndResult != string(SmartIdEndResultOK) {
		endResult := "Unknown failure"
		if response.Result != nil {
			endResult = response.Result.EndResult
		}
		v.result.AddError("Session failed: " + endResult)
	}

	if response.Cert == nil || response.Cert.Value == "" {
		v.result.AddError("Certificate is missing.")
	}

	if response.Signature == nil || response.Signature.Value == "" {
		v.result.AddError("Signature is missing.")
	}
}

// validateSessionSecretDigest verifies the session secret digest matches the expected value
func (v *CallbackURLValidator) validateSessionSecretDigest() {
	expectedDigest := v.computeSessionSecretDigest(v.entity.SessionSecret)
	if v.entity.SessionSecretDigest != expectedDigest {
		v.result.AddError("Session secret digest mismatch.")
	}
}

// validateUserChallengeVerifier confirms the user challenge verifier matches the expected challenge
func (v *CallbackURLValidator) validateUserChallengeVerifier() {
	hash := sha256.Sum256([]byte(v.entity.UserChallengeVerifier))
	computed := v.base64URLEncode(hash[:])

	expectedUserChallenge := ""
	if v.entity.AuthenticationResponse.Signature != nil {
		expectedUserChallenge = v.entity.AuthenticationResponse.Signature.UserChallenge
	}

	if computed != expectedUserChallenge {
		v.result.AddError("User challenge verifier mismatch.")
	}
}

// computeSessionSecretDigest computes the expected session secret digest from the provided secret
func (v *CallbackURLValidator) computeSessionSecretDigest(sessionSecret string) string {
	secretBytes, err := base64.StdEncoding.DecodeString(sessionSecret)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(secretBytes)
	return v.base64URLEncode(hash[:])
}

// base64URLEncode encodes a byte slice to a URL-safe Base64 string (RFC 4648)
func (v *CallbackURLValidator) base64URLEncode(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	// Convert to URL-safe encoding
	encoded = strings.ReplaceAll(encoded, "+", "-")
	encoded = strings.ReplaceAll(encoded, "/", "_")
	encoded = strings.TrimRight(encoded, "=")
	return encoded
}
