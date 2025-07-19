package smartid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

// AuthenticationRequestBuilder provides a developer-friendly way to construct Smart-ID authentication requests
type AuthenticationRequestBuilder struct {
	relyingPartyUUID   string
	relyingPartyName   string
	payload            *DeviceLinkAuthRequest
	currentInteraction Interaction
}

// NewAuthenticationRequestBuilder creates a new AuthenticationRequestBuilder instance
func NewAuthenticationRequestBuilder(relyingPartyUUID, relyingPartyName string) *AuthenticationRequestBuilder {
	rpChallenge := generateRPChallenge()

	defaultInteraction := &DisplayTextAndPINInteraction{
		Type:          "displayTextAndPIN",
		DisplayText60: "Authenticate with Smart-ID",
	}

	payload := &DeviceLinkAuthRequest{
		RelyingPartyUUID:  relyingPartyUUID,
		RelyingPartyName:  relyingPartyName,
		CertificateLevel:  CertificateLevelQualified,
		SignatureProtocol: SignatureProtocolACSP_V2,
		SignatureProtocolParameters: SignatureProtocolParams{
			RPChallenge:        rpChallenge,
			SignatureAlgorithm: SignatureAlgorithmRSASSA_PSS,
			SignatureAlgorithmParameters: SignatureAlgorithmParameters{
				HashAlgorithm: HashAlgorithmSHA512,
			},
		},
		Interactions: encodeInteraction(defaultInteraction),
	}

	return &AuthenticationRequestBuilder{
		relyingPartyUUID:   relyingPartyUUID,
		relyingPartyName:   relyingPartyName,
		payload:            payload,
		currentInteraction: defaultInteraction,
	}
}

// WithInitialCallbackURL sets the callback URL for Web2App or App2App flows
func (b *AuthenticationRequestBuilder) WithInitialCallbackURL(url string) *AuthenticationRequestBuilder {
	b.payload.InitialCallbackURL = url
	return b
}

// WithCertificateLevel sets desired certificate level
func (b *AuthenticationRequestBuilder) WithCertificateLevel(level CertificateLevel) *AuthenticationRequestBuilder {
	b.payload.CertificateLevel = level
	return b
}

// WithHashAlgorithm sets hash algorithm for signature generation
func (b *AuthenticationRequestBuilder) WithHashAlgorithm(hash HashAlgorithm) *AuthenticationRequestBuilder {
	b.payload.SignatureProtocolParameters.SignatureAlgorithmParameters.HashAlgorithm = hash
	return b
}

// WithRequestProperties adds request-specific properties
func (b *AuthenticationRequestBuilder) WithRequestProperties(props *RequestProperties) *AuthenticationRequestBuilder {
	b.payload.RequestProperties = props
	return b
}

// WithCapabilities adds custom capabilities to the request
func (b *AuthenticationRequestBuilder) WithCapabilities(capabilities map[string]interface{}) *AuthenticationRequestBuilder {
	b.payload.Capabilities = capabilities
	return b
}

// WithInteractions defines the user-facing interaction shown on the Smart-ID app
func (b *AuthenticationRequestBuilder) WithInteractions(interaction Interaction) *AuthenticationRequestBuilder {
	b.currentInteraction = interaction
	b.payload.Interactions = encodeInteraction(interaction)
	return b
}

// WithVCType switches to notification authentication request builder
func (b *AuthenticationRequestBuilder) WithVCType(vcType string) *NotificationRequestBuilder {
	return NewNotificationRequestBuilder(b.payload, vcType)
}

// Build finalizes and returns the request payload for API consumption
func (b *AuthenticationRequestBuilder) Build() *DeviceLinkAuthRequest {
	return b.payload
}

// NotificationRequestBuilder handles notification-specific request building
type NotificationRequestBuilder struct {
	payload *NotificationAuthRequest
}

// NewNotificationRequestBuilder creates a new NotificationRequestBuilder
func NewNotificationRequestBuilder(basePayload *DeviceLinkAuthRequest, vcType string) *NotificationRequestBuilder {
	notificationPayload := &NotificationAuthRequest{
		DeviceLinkAuthRequest: *basePayload,
		VCType:                vcType,
	}

	return &NotificationRequestBuilder{
		payload: notificationPayload,
	}
}

// Build finalizes and returns the notification request payload
func (b *NotificationRequestBuilder) Build() *NotificationAuthRequest {
	return b.payload
}

// encodeInteraction encodes an interaction to base64 JSON
func encodeInteraction(interaction Interaction) string {
	interactions := []Interaction{interaction}
	jsonBytes, err := json.Marshal(interactions)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(jsonBytes)
}

// generateRPChallenge generates a random base64-encoded challenge
func generateRPChallenge() string {
	bytes := make([]byte, 64)
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

// GenerateSemanticsIdentifier creates a semantics identifier string
func GenerateSemanticsIdentifier(semanticsIdentifierType, countryCode, identityNumber string) string {
	return semanticsIdentifierType + countryCode + "-" + identityNumber
}
