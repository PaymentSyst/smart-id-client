package smartid

import (
	"testing"
	"time"
)

// Test certificate for testing purposes (self-signed)
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTMwODEyMDE1NzUyWhcNMjMwODEwMDE1NzUyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwpniVYhz0i9cFE1bNDQo+4m+4xjFUBfK2xLQfJR8qjf6Q9r4MHQEF1V8
5yj+2k+2FGhJkfLHzrZ8FQHZ7mI+GjQwz0x1Dn+WvN3V0qjZZO0l8u5+LYvQ6Y1x
dGhJzKdLRJ7pBq6sHQ/Hsl8/Hj1z2K+n3w+7o7qJ+P6I8s1r2YcZG1K5xJ1l8j1j
1qJ7r2Z8o8Q1V8h0s8w2z0r3Y1H5o1i1V8u2P6J+k5F8B0s4w8y2z0r7s1V5o1j1
V8u2F6J+v5G8A0s8w8y1z0r8s1V5o1j1V9u2F7J+w5J8C0s8w8y1z0r9s1V5o1j1
VKu2F8J+x5J8E0s8w8y1z0r0s1V5o1j1VEu2G9J+y5J8G0s8w8y1z0rQIDAQAB
o1AwTjAdBgNVHQ4EFgQUkqR1LKSevoFE63FYDuuvn+ul6SwwHwYDVR0jBBgwFoAU
kqR1LKSevoFE63FYDuuvn+ul6SwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUF
AAOCAQEAi3XBk6bw2j1J2j0r1Qz1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1
J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1
J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1
J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1J3j1J+j1J2j1
-----END CERTIFICATE-----`

func TestNewAuthenticationRequestBuilder(t *testing.T) {
	builder := NewAuthenticationRequestBuilder("test-uuid", "test-name")

	if builder == nil {
		t.Fatal("Expected builder to be created")
	}

	request := builder.Build()

	if request.RelyingPartyUUID != "test-uuid" {
		t.Errorf("Expected RelyingPartyUUID to be 'test-uuid', got %s", request.RelyingPartyUUID)
	}

	if request.RelyingPartyName != "test-name" {
		t.Errorf("Expected RelyingPartyName to be 'test-name', got %s", request.RelyingPartyName)
	}

	if request.CertificateLevel != CertificateLevelQualified {
		t.Errorf("Expected default certificate level to be QUALIFIED, got %s", request.CertificateLevel)
	}

	if request.SignatureProtocol != SignatureProtocolACSP_V2 {
		t.Errorf("Expected signature protocol to be ACSP_V2, got %s", request.SignatureProtocol)
	}
}

func TestAuthenticationRequestBuilderChaining(t *testing.T) {
	builder := NewAuthenticationRequestBuilder("test-uuid", "test-name")

	request := builder.
		WithInitialCallbackURL("https://example.com/callback").
		WithCertificateLevel(CertificateLevelAdvanced).
		WithHashAlgorithm(HashAlgorithmSHA256).
		WithRequestProperties(&RequestProperties{
			ShareMdClientIPAddress: true,
		}).
		WithCapabilities(map[string]interface{}{
			"test": "value",
		}).
		WithInteractions(&DisplayTextAndPINInteraction{
			Type:          "displayTextAndPIN",
			DisplayText60: "Test message",
		}).
		Build()

	if request.InitialCallbackURL != "https://example.com/callback" {
		t.Errorf("Expected callback URL to be set")
	}

	if request.CertificateLevel != CertificateLevelAdvanced {
		t.Errorf("Expected certificate level to be ADVANCED")
	}

	if request.SignatureProtocolParameters.SignatureAlgorithmParameters.HashAlgorithm != HashAlgorithmSHA256 {
		t.Errorf("Expected hash algorithm to be SHA256")
	}

	if request.RequestProperties == nil || !request.RequestProperties.ShareMdClientIPAddress {
		t.Errorf("Expected request properties to be set")
	}

	if request.Capabilities == nil || request.Capabilities["test"] != "value" {
		t.Errorf("Expected capabilities to be set")
	}
}

func TestNotificationRequestBuilder(t *testing.T) {
	builder := NewAuthenticationRequestBuilder("test-uuid", "test-name")
	notificationBuilder := builder.WithVCType("numeric4")

	if notificationBuilder == nil {
		t.Fatal("Expected notification builder to be created")
	}

	request := notificationBuilder.Build()

	if request.VCType != "numeric4" {
		t.Errorf("Expected VCType to be 'numeric4', got %s", request.VCType)
	}

	if request.RelyingPartyUUID != "test-uuid" {
		t.Errorf("Expected RelyingPartyUUID to be inherited")
	}
}

func TestSmartIdClientCreation(t *testing.T) {
	config := &SmartIdClientConfig{
		RelyingPartyUUID: "test-uuid",
		RelyingPartyName: "test-name",
		HostURL:          "https://example.com",
		APIVersion:       "v3",
		Debug:            true,
	}

	client := NewSmartIdAuthClient(config)

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	if client.config.RelyingPartyUUID != "test-uuid" {
		t.Errorf("Expected config to be set correctly")
	}

	if client.GetHostURL() != "https://example.com/v3" {
		t.Errorf("Expected base URL to be constructed correctly, got %s", client.GetHostURL())
	}
}

func TestSmartIdClientConfiguration(t *testing.T) {
	config := &SmartIdClientConfig{
		RelyingPartyUUID: "test-uuid",
		RelyingPartyName: "test-name",
	}

	client := NewSmartIdAuthClient(config)

	// Test method chaining
	client.
		SetAPIEndpoint("https://new-endpoint.com", "v4").
		SetSchemeName("test-scheme").
		SetBrokeredRpName("test-broker").
		SetPublicSSLKeys("sha256//key1;sha256//key2")

	if client.GetHostURL() != "https://new-endpoint.com/v4" {
		t.Errorf("Expected endpoint to be updated")
	}

	if client.schemeName != "test-scheme" {
		t.Errorf("Expected scheme name to be set")
	}

	if client.brokeredRpName != "test-broker" {
		t.Errorf("Expected brokered RP name to be set")
	}

	if len(client.publicSSLKeys) != 2 {
		t.Errorf("Expected 2 SSL keys, got %d", len(client.publicSSLKeys))
	}
}

func TestAuthResult(t *testing.T) {
	result := NewAuthResult()

	if !result.IsValid() {
		t.Errorf("Expected result to be valid initially")
	}

	if result.HasError() {
		t.Errorf("Expected no errors initially")
	}

	result.AddError("test error")

	if result.IsValid() {
		t.Errorf("Expected result to be invalid after adding error")
	}

	if !result.HasError() {
		t.Errorf("Expected result to have errors")
	}

	errors := result.GetErrors()
	if len(errors) != 1 || errors[0] != "test error" {
		t.Errorf("Expected one error with correct message")
	}

	identity := &AuthenticationIdentity{
		GivenName: "Test",
		SurName:   "User",
	}

	result.SetIdentity(identity)

	if result.GetIdentity().GivenName != "Test" {
		t.Errorf("Expected identity to be set correctly")
	}
}

func TestAuthenticationIdentity(t *testing.T) {
	identity := NewAuthenticationIdentity()

	identity.GivenName = "John"
	identity.SurName = "Doe"
	identity.IdentityCode = "12345"
	identity.Country = "EE"
	identity.ValidFrom = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	identity.ValidTo = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	if identity.GetGivenName() != "John" {
		t.Errorf("Expected given name to be 'John'")
	}

	if identity.GetSurName() != "Doe" {
		t.Errorf("Expected surname to be 'Doe'")
	}

	if identity.GetIdentityCode() != "12345" {
		t.Errorf("Expected identity code to be '12345'")
	}

	if identity.GetCountry() != "EE" {
		t.Errorf("Expected country to be 'EE'")
	}

	if identity.GetValidFrom().Year() != 2020 {
		t.Errorf("Expected valid from year to be 2020")
	}

	if identity.GetValidTo().Year() != 2025 {
		t.Errorf("Expected valid to year to be 2025")
	}
}

func TestCallbackURLValidator(t *testing.T) {
	entity := &CallbackValidationEntity{
		SessionSecretDigest:   "test-digest",
		UserChallengeVerifier: "test-verifier",
		SessionSecret:         "dGVzdC1zZWNyZXQ=", // base64 encoded "test-secret"
		SchemeName:            "smart-id",
		AuthenticationResponse: AuthenticationResponse{
			State: "COMPLETE",
			Result: &AuthenticationResult{
				EndResult:      "OK",
				DocumentNumber: "TEST123",
			},
			Cert: &CertificateInfo{
				Value:            "test-cert",
				CertificateLevel: CertificateLevelQualified,
			},
			Signature: &SignatureInfo{
				Value:         "test-signature",
				UserChallenge: "test-challenge",
			},
		},
	}

	validator := NewCallbackURLValidator(entity)
	result := validator.Validate().GetResult()

	// Should have errors due to digest/challenge mismatch
	if !result.HasError() {
		t.Errorf("Expected validation to have errors")
	}
}

func TestGenerateSemanticsIdentifier(t *testing.T) {
	identifier := GenerateSemanticsIdentifier("PNOEE", "EE", "12345678901")
	expected := "PNOEEEE-12345678901"

	if identifier != expected {
		t.Errorf("Expected identifier '%s', got '%s'", expected, identifier)
	}
}

func TestIsSessionSuccessful(t *testing.T) {
	// Test successful session
	successfulResponse := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult: "OK",
		},
	}

	if !IsSessionSuccessful(successfulResponse) {
		t.Errorf("Expected session to be successful")
	}

	// Test failed session
	failedResponse := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult: "USER_REFUSED",
		},
	}

	if IsSessionSuccessful(failedResponse) {
		t.Errorf("Expected session to be unsuccessful")
	}

	// Test incomplete session
	incompleteResponse := AuthenticationResponse{
		State: "RUNNING",
	}

	if IsSessionSuccessful(incompleteResponse) {
		t.Errorf("Expected session to be unsuccessful")
	}
}

func TestSmartIdErrors(t *testing.T) {
	// Test base error
	baseError := NewSmartIdError("test message")
	if baseError.Error() != "test message" {
		t.Errorf("Expected error message to be 'test message'")
	}

	// Test user refused error
	userRefusedError := NewSmartIdUserRefusedError()
	if userRefusedError.Error() != "User refused Smart-ID operation." {
		t.Errorf("Expected user refused error message")
	}

	// Test timeout error
	timeoutError := NewSmartIdTimeoutError()
	if timeoutError.Error() != "Smart-ID session timed out." {
		t.Errorf("Expected timeout error message")
	}

	// Test session failed error
	sessionFailedError := NewSmartIdSessionFailedError("PROTOCOL_FAILURE")
	if sessionFailedError.Error() != "Smart-ID session failed: PROTOCOL_FAILURE" {
		t.Errorf("Expected session failed error message")
	}
	if sessionFailedError.EndResult != "PROTOCOL_FAILURE" {
		t.Errorf("Expected end result to be set")
	}
}

func TestCertificationLevelOrder(t *testing.T) {
	advancedLevel := CertificationLevelOrder[CertificateLevelAdvanced]
	qualifiedLevel := CertificationLevelOrder[CertificateLevelQualified]

	if advancedLevel >= qualifiedLevel {
		t.Errorf("Expected QUALIFIED level to be higher than ADVANCED")
	}
}

func TestInteractionTypes(t *testing.T) {
	// Test DisplayTextAndPIN interaction
	displayTextInteraction := &DisplayTextAndPINInteraction{
		Type:          "displayTextAndPIN",
		DisplayText60: "Test message",
	}

	if displayTextInteraction.GetType() != "displayTextAndPIN" {
		t.Errorf("Expected interaction type to be 'displayTextAndPIN'")
	}

	// Test ConfirmationMessage interaction
	confirmationInteraction := &ConfirmationMessageInteraction{
		Type:           "confirmationMessage",
		DisplayText200: "Longer test message",
	}

	if confirmationInteraction.GetType() != "confirmationMessage" {
		t.Errorf("Expected interaction type to be 'confirmationMessage'")
	}

	// Test ConfirmationMessageAndVerificationCodeChoice interaction
	confirmationWithVCInteraction := &ConfirmationMessageAndVerificationCodeChoiceInteraction{
		Type:           "confirmationMessageAndVerificationCodeChoice",
		DisplayText200: "Test with VC choice",
	}

	if confirmationWithVCInteraction.GetType() != "confirmationMessageAndVerificationCodeChoice" {
		t.Errorf("Expected interaction type to be 'confirmationMessageAndVerificationCodeChoice'")
	}
}

func TestVerificationCodeComputation(t *testing.T) {
	client := NewSmartIdAuthClient(&SmartIdClientConfig{
		RelyingPartyUUID: "test",
		RelyingPartyName: "test",
	})

	// Test with known base64 challenge
	testChallenge := "dGVzdC1jaGFsbGVuZ2U=" // base64 encoded "test-challenge"
	code := client.computeVerificationCode(testChallenge)

	if len(code) != 4 {
		t.Errorf("Expected verification code to be 4 digits, got %s", code)
	}

	// Verify it's all digits
	for _, char := range code {
		if char < '0' || char > '9' {
			t.Errorf("Expected verification code to contain only digits, got %s", code)
		}
	}
}

func TestDeviceLinkTypes(t *testing.T) {
	qr := DeviceLinkTypeQR
	web2app := DeviceLinkTypeWeb2App
	app2app := DeviceLinkTypeApp2App

	if qr != "QR" {
		t.Errorf("Expected QR type to be 'QR'")
	}

	if web2app != "Web2App" {
		t.Errorf("Expected Web2App type to be 'Web2App'")
	}

	if app2app != "App2App" {
		t.Errorf("Expected App2App type to be 'App2App'")
	}
}

func TestHashAlgorithms(t *testing.T) {
	algorithms := []HashAlgorithm{
		HashAlgorithmSHA256,
		HashAlgorithmSHA384,
		HashAlgorithmSHA512,
		HashAlgorithmSHA3_256,
		HashAlgorithmSHA3_384,
		HashAlgorithmSHA3_512,
	}

	expected := []string{
		"SHA-256",
		"SHA-384",
		"SHA-512",
		"SHA3-256",
		"SHA3-384",
		"SHA3-512",
	}

	for i, alg := range algorithms {
		if string(alg) != expected[i] {
			t.Errorf("Expected algorithm %d to be '%s', got '%s'", i, expected[i], string(alg))
		}
	}
}

func TestSmartIdEndResults(t *testing.T) {
	results := map[SmartIdEndResult]string{
		SmartIdEndResultOK:                                         "OK",
		SmartIdEndResultUserRefusedInteraction:                     "USER_REFUSED_INTERACTION",
		SmartIdEndResultProtocolFailure:                            "PROTOCOL_FAILURE",
		SmartIdEndResultServerError:                                "SERVER_ERROR",
		SmartIdEndResultTimeout:                                    "TIMEOUT",
		SmartIdEndResultDocumentUnusable:                           "DOCUMENT_UNUSABLE",
		SmartIdEndResultWrongVC:                                    "WRONG_VC",
		SmartIdEndResultRequiredInteractionNotSupportedByApp:       "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP",
		SmartIdEndResultUserRefusedDisplayTextAndPIN:               "USER_REFUSED_DISPLAYTEXTANDPIN",
		SmartIdEndResultUserRefusedConfirmationMessage:             "USER_REFUSED_CONFIRMATIONMESSAGE",
		SmartIdEndResultUserRefusedConfirmationMessageWithVCChoice: "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE",
		SmartIdEndResultUserRefusedCertChoice:                      "USER_REFUSED_CERT_CHOICE",
	}

	for result, expected := range results {
		if string(result) != expected {
			t.Errorf("Expected result '%s', got '%s'", expected, string(result))
		}
	}
}

// Benchmark tests
func BenchmarkAuthenticationRequestBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		builder := NewAuthenticationRequestBuilder("test-uuid", "test-name")
		builder.
			WithInitialCallbackURL("https://example.com/callback").
			WithCertificateLevel(CertificateLevelQualified).
			WithInteractions(&DisplayTextAndPINInteraction{
				Type:          "displayTextAndPIN",
				DisplayText60: "Test message",
			}).
			Build()
	}
}

func BenchmarkVerificationCodeComputation(b *testing.B) {
	client := NewSmartIdAuthClient(&SmartIdClientConfig{
		RelyingPartyUUID: "test",
		RelyingPartyName: "test",
	})

	testChallenge := "dGVzdC1jaGFsbGVuZ2U="

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.computeVerificationCode(testChallenge)
	}
}

func BenchmarkCallbackParamGeneration(b *testing.B) {
	client := NewSmartIdAuthClient(&SmartIdClientConfig{
		RelyingPartyUUID: "test",
		RelyingPartyName: "test",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.GenerateCallbackParam()
	}
}
