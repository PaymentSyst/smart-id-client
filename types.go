package smartid

import (
	"crypto/x509"
)

// HashAlgorithm represents the hash algorithms supported by Smart-ID
type HashAlgorithm string

const (
	HashAlgorithmSHA256   HashAlgorithm = "SHA-256"
	HashAlgorithmSHA384   HashAlgorithm = "SHA-384"
	HashAlgorithmSHA512   HashAlgorithm = "SHA-512"
	HashAlgorithmSHA3_256 HashAlgorithm = "SHA3-256"
	HashAlgorithmSHA3_384 HashAlgorithm = "SHA3-384"
	HashAlgorithmSHA3_512 HashAlgorithm = "SHA3-512"
)

// SmartIdEndResult represents the possible end results of a Smart-ID session
type SmartIdEndResult string

const (
	SmartIdEndResultOK                                         SmartIdEndResult = "OK"
	SmartIdEndResultUserRefusedInteraction                     SmartIdEndResult = "USER_REFUSED_INTERACTION"
	SmartIdEndResultProtocolFailure                            SmartIdEndResult = "PROTOCOL_FAILURE"
	SmartIdEndResultServerError                                SmartIdEndResult = "SERVER_ERROR"
	SmartIdEndResultTimeout                                    SmartIdEndResult = "TIMEOUT"
	SmartIdEndResultDocumentUnusable                           SmartIdEndResult = "DOCUMENT_UNUSABLE"
	SmartIdEndResultWrongVC                                    SmartIdEndResult = "WRONG_VC"
	SmartIdEndResultRequiredInteractionNotSupportedByApp       SmartIdEndResult = "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP"
	SmartIdEndResultUserRefusedDisplayTextAndPIN               SmartIdEndResult = "USER_REFUSED_DISPLAYTEXTANDPIN"
	SmartIdEndResultUserRefusedConfirmationMessage             SmartIdEndResult = "USER_REFUSED_CONFIRMATIONMESSAGE"
	SmartIdEndResultUserRefusedConfirmationMessageWithVCChoice SmartIdEndResult = "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE"
	SmartIdEndResultUserRefusedCertChoice                      SmartIdEndResult = "USER_REFUSED_CERT_CHOICE"
)

// CertificateLevel represents the certificate levels
type CertificateLevel string

const (
	CertificateLevelAdvanced  CertificateLevel = "ADVANCED"
	CertificateLevelQualified CertificateLevel = "QUALIFIED"
)

// SignatureProtocol represents the signature protocols
type SignatureProtocol string

const (
	SignatureProtocolACSP_V2 SignatureProtocol = "ACSP_V2"
)

// SignatureAlgorithm represents the signature algorithms
type SignatureAlgorithm string

const (
	SignatureAlgorithmRSASSA_PSS SignatureAlgorithm = "rsassa-pss"
)

// CertificationLevelOrder maps certificate levels to their priority order
var CertificationLevelOrder = map[CertificateLevel]int{
	CertificateLevelAdvanced:  1,
	CertificateLevelQualified: 2,
}

// SmartIdClientConfig represents the configuration for the Smart-ID client
type SmartIdClientConfig struct {
	RelyingPartyUUID string
	RelyingPartyName string
	HostURL          string
	APIVersion       string
	BrokeredRpName   string
	PinnedCerts      []*x509.Certificate
	PublicSSLKeys    string
	Debug            bool
}

// Interaction represents the different types of user interactions
type Interaction interface {
	GetType() string
}

// DisplayTextAndPINInteraction represents a display text and PIN interaction
type DisplayTextAndPINInteraction struct {
	Type          string `json:"type"`
	DisplayText60 string `json:"displayText60"`
}

func (d DisplayTextAndPINInteraction) GetType() string {
	return d.Type
}

// ConfirmationMessageInteraction represents a confirmation message interaction
type ConfirmationMessageInteraction struct {
	Type           string `json:"type"`
	DisplayText200 string `json:"displayText200"`
}

func (c ConfirmationMessageInteraction) GetType() string {
	return c.Type
}

// ConfirmationMessageAndVerificationCodeChoiceInteraction represents confirmation with VC choice
type ConfirmationMessageAndVerificationCodeChoiceInteraction struct {
	Type           string `json:"type"`
	DisplayText200 string `json:"displayText200"`
}

func (c ConfirmationMessageAndVerificationCodeChoiceInteraction) GetType() string {
	return c.Type
}

// DeviceLinkAuthRequest represents a device link authentication request
type DeviceLinkAuthRequest struct {
	RelyingPartyUUID            string                  `json:"relyingPartyUUID"`
	RelyingPartyName            string                  `json:"relyingPartyName"`
	InitialCallbackURL          string                  `json:"initialCallbackUrl,omitempty"`
	CertificateLevel            CertificateLevel        `json:"certificateLevel,omitempty"`
	SignatureProtocol           SignatureProtocol       `json:"signatureProtocol"`
	SignatureProtocolParameters SignatureProtocolParams `json:"signatureProtocolParameters"`
	Interactions                string                  `json:"interactions"`
	RequestProperties           *RequestProperties      `json:"requestProperties,omitempty"`
	Capabilities                map[string]interface{}  `json:"capabilities,omitempty"`
}

// NotificationAuthRequest extends DeviceLinkAuthRequest for notification authentication
type NotificationAuthRequest struct {
	DeviceLinkAuthRequest
	VCType string `json:"vcType"`
}

// SignatureProtocolParams represents signature protocol parameters
type SignatureProtocolParams struct {
	RPChallenge                  string                       `json:"rpChallenge"`
	SignatureAlgorithm           SignatureAlgorithm           `json:"signatureAlgorithm"`
	SignatureAlgorithmParameters SignatureAlgorithmParameters `json:"signatureAlgorithmParameters"`
}

// SignatureAlgorithmParameters represents signature algorithm parameters
type SignatureAlgorithmParameters struct {
	HashAlgorithm HashAlgorithm `json:"hashAlgorithm"`
}

// RequestProperties represents request properties
type RequestProperties struct {
	ShareMdClientIPAddress bool `json:"shareMdClientIpAddress,omitempty"`
}

// DeviceLinkAuthResponse represents a device link authentication response
type DeviceLinkAuthResponse struct {
	SessionID      string `json:"sessionID"`
	SessionToken   string `json:"sessionToken"`
	SessionSecret  string `json:"sessionSecret"`
	DeviceLinkBase string `json:"deviceLinkBase"`
}

// NotificationAuthResponse represents a notification authentication response
type NotificationAuthResponse struct {
	SessionID        string `json:"sessionID"`
	VerificationCode string `json:"verificationCode"`
}

// AuthenticationResponse represents the final authentication response
type AuthenticationResponse struct {
	State               string                `json:"state"`
	Result              *AuthenticationResult `json:"result,omitempty"`
	SignatureProtocol   string                `json:"signatureProtocol"`
	Signature           *SignatureInfo        `json:"signature,omitempty"`
	Cert                *CertificateInfo      `json:"cert,omitempty"`
	InteractionTypeUsed string                `json:"interactionTypeUsed,omitempty"`
	FlowType            string                `json:"flowType,omitempty"`
}

// AuthenticationResult represents the result portion of an authentication response
type AuthenticationResult struct {
	EndResult      string `json:"endResult"`
	DocumentNumber string `json:"documentNumber"`
}

// SignatureInfo represents signature information in the response
type SignatureInfo struct {
	Value                        string                            `json:"value"`
	UserChallenge                string                            `json:"userChallenge,omitempty"`
	ServerRandom                 string                            `json:"serverRandom,omitempty"`
	SignatureAlgorithm           string                            `json:"signatureAlgorithm,omitempty"`
	SignatureAlgorithmParameters *ResponseSignatureAlgorithmParams `json:"signatureAlgorithmParameters,omitempty"`
}

// ResponseSignatureAlgorithmParams represents signature algorithm parameters in response
type ResponseSignatureAlgorithmParams struct {
	HashAlgorithm    string            `json:"hashAlgorithm"`
	MaskGenAlgorithm *MaskGenAlgorithm `json:"maskGenAlgorithm,omitempty"`
	SaltLength       int               `json:"saltLength,omitempty"`
	TrailerField     string            `json:"trailerField,omitempty"`
}

// MaskGenAlgorithm represents mask generation algorithm parameters
type MaskGenAlgorithm struct {
	Algorithm  string                  `json:"algorithm"`
	Parameters *MaskGenAlgorithmParams `json:"parameters,omitempty"`
}

// MaskGenAlgorithmParams represents mask generation algorithm parameters
type MaskGenAlgorithmParams struct {
	HashAlgorithm string `json:"hashAlgorithm"`
}

// CertificateInfo represents certificate information in the response
type CertificateInfo struct {
	Value            string           `json:"value"`
	CertificateLevel CertificateLevel `json:"certificateLevel"`
}

// CallbackValidationEntity represents entity for callback validation
type CallbackValidationEntity struct {
	SessionSecretDigest    string                 `json:"sessionSecretDigest"`
	UserChallengeVerifier  string                 `json:"userChallengeVerifier"`
	SessionSecret          string                 `json:"sessionSecret"`
	SchemeName             string                 `json:"schemeName"`
	AuthenticationResponse AuthenticationResponse `json:"authenticationResponse"`
}

// AuthenticationValidationResult represents the result of authentication validation
type AuthenticationValidationResult struct {
	HasError bool                    `json:"hasError"`
	Errors   []string                `json:"errors"`
	Identity *AuthenticationIdentity `json:"identity,omitempty"`
}

// AuthenticationIdentity is defined in auth_identity.go

// DeviceLinkType represents the type of device link
type DeviceLinkType string

const (
	DeviceLinkTypeQR      DeviceLinkType = "QR"
	DeviceLinkTypeWeb2App DeviceLinkType = "Web2App"
	DeviceLinkTypeApp2App DeviceLinkType = "App2App"
)

// DeviceLinkOptions represents options for creating device links
type DeviceLinkOptions struct {
	DeviceLinkType DeviceLinkType `json:"deviceLinkType"`
	Lang           string         `json:"lang,omitempty"`
	ElapsedSeconds int            `json:"elapsedSeconds,omitempty"`
}

// PollOptions represents options for polling session status
type PollOptions struct {
	MaxWaitMs      int `json:"maxWaitMs,omitempty"`
	PollIntervalMs int `json:"pollIntervalMs,omitempty"`
	MaxAttempts    int `json:"maxAttempts,omitempty"`
}

// IsSessionSuccessful checks if an authentication response represents a successful session
func IsSessionSuccessful(status AuthenticationResponse) bool {
	return status.State == "COMPLETE" &&
		status.Result != nil &&
		status.Result.EndResult == string(SmartIdEndResultOK)
}

// GenerateSemanticsIdentifier is defined in auth_request_builder.go
