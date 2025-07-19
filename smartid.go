// Package smartid provides a comprehensive Go client library for integrating with the Smart-ID REST API v3.
//
// This library offers a modern, developer-friendly integration with the official Smart-ID REST API v3
// from SK ID Solutions, supporting strong, secure electronic identity authentication and digital signing
// for users in Estonia, Latvia, and Lithuania.
//
// The library provides:
//   - Device Link Authentication (anonymous, by ETSI, by document)
//   - Notification Authentication (by ETSI, by document)
//   - Comprehensive response validation including certificate trust verification
//   - Callback URL validation for Web2App/App2App flows
//   - Authentication identity extraction
//   - Signature verification
//   - Certificate policy validation
//
// Example usage:
//
//	client := smartid.NewSmartIdAuthClient(&smartid.SmartIdClientConfig{
//		RelyingPartyUUID: "00000000-0000-4000-8000-000000000000",
//		RelyingPartyName: "DEMO",
//		HostURL:          "https://sid.demo.sk.ee/smart-id-rp",
//		Debug:            true,
//	})
//
//	builder := smartid.NewAuthenticationRequestBuilder(
//		"00000000-0000-4000-8000-000000000000",
//		"DEMO",
//	)
//
//	request := builder.
//		WithInitialCallbackURL("https://example.com/callback").
//		WithCertificateLevel(smartid.CertificateLevelQualified).
//		WithInteractions(&smartid.DisplayTextAndPINInteraction{
//			Type:          "displayTextAndPIN",
//			DisplayText60: "Authenticate with Smart-ID",
//		}).
//		Build()
//
//	response, sessionStartTime, err := client.GetAuthenticateAnonymousDeviceLink(request)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Poll for result
//	authResponse, err := client.PollForSessionResult(response.SessionID, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Validate the response
//	validator, err := smartid.NewAuthenticationResponseValidator("/path/to/ca/certs", true)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	result := validator.Validate(authResponse, request).GetResult()
//	if result.HasError() {
//		log.Printf("Validation errors: %v", result.GetErrors())
//	} else {
//		identity := result.GetIdentity()
//		log.Printf("Authenticated user: %s %s", identity.GetGivenName(), identity.GetSurName())
//	}
package smartid
