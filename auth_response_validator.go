package smartid

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// AuthenticationResponseValidator provides comprehensive validation of Smart-ID authentication responses
type AuthenticationResponseValidator struct {
	trustedCACertificates []string
	caStore               []*x509.Certificate
	resolvedPath          string
	debug                 bool
	schemeName            string
	interactionTypeUsed   string
	brokeredRpName        string
	flowType              string
	result                *AuthResult
}

// NewAuthenticationResponseValidator creates a new validator instance
func NewAuthenticationResponseValidator(resourcesLocation string, debug bool) (*AuthenticationResponseValidator, error) {
	if resourcesLocation == "" {
		return nil, fmt.Errorf("resourcesLocation is required and must be a valid path to the certificate directory")
	}

	validator := &AuthenticationResponseValidator{
		trustedCACertificates: make([]string, 0),
		caStore:               make([]*x509.Certificate, 0),
		resolvedPath:          resourcesLocation,
		debug:                 debug,
		schemeName:            "smart-id",
		interactionTypeUsed:   "",
		brokeredRpName:        "",
		flowType:              "",
		result:                NewAuthResult(),
	}

	err := validator.loadCACertificates(resourcesLocation)
	if err != nil {
		return nil, err
	}

	return validator, nil
}

// Validate runs core response and certificate validation logic
func (v *AuthenticationResponseValidator) Validate(authenticationResponse *AuthenticationResponse, payload interface{}) *AuthenticationResponseValidator {
	v.result = NewAuthResult()

	v.assertAuthenticationResponseIsCompleteAndValid(authenticationResponse)

	if !v.result.HasError() {
		certPem := v.wrapCertificate(authenticationResponse.Cert.Value)
		cert, err := v.parseCertificate(certPem)
		if err != nil {
			v.result.AddError("Failed to parse certificate: " + err.Error())
			return v
		}

		if !v.verifyCertificateExpiry(cert) {
			v.result.AddError("Certificate has expired.")
		}

		if !v.isCertificateTrusted(authenticationResponse.Cert.Value) {
			v.result.AddError("Certificate is not trusted.")
		}

		var requestLevel CertificateLevel
		switch req := payload.(type) {
		case *DeviceLinkAuthRequest:
			requestLevel = req.CertificateLevel
		case *NotificationAuthRequest:
			requestLevel = req.CertificateLevel
		}

		if !v.isEqualOrAbove(authenticationResponse.Cert.CertificateLevel, requestLevel) {
			v.result.AddError("Certificate level is not correct.")
		}

		if !v.checkSmartIDSchemeIdentification(cert) {
			v.result.AddError("Certificate does not meet Smart-ID Scheme Identification (End-Entity Certificate) requirements")
		}

		if !v.result.HasError() {
			identity := v.constructAuthenticationIdentity(authenticationResponse, cert)
			v.result.SetIdentity(identity)
		}
	}

	return v
}

// WithCallbackURLValidate runs callback URL validator for Web2App/App2App flows
func (v *AuthenticationResponseValidator) WithCallbackURLValidate(entity *CallbackValidationEntity) *AuthenticationResponseValidator {
	callbackValidator := NewCallbackURLValidator(entity)
	callbackResult := callbackValidator.Validate().GetResult()

	if callbackResult.HasError() {
		for _, err := range callbackResult.GetErrors() {
			v.result.AddError(err)
		}
	}

	return v
}

// CheckIfHasAllowedCertificatePolicies checks if the certificate contains at least one allowed policy OID
func (v *AuthenticationResponseValidator) CheckIfHasAllowedCertificatePolicies(pemCert string, allowedOids []string) bool {
	cert, err := v.parseCertificate(pemCert)
	if err != nil {
		v.result.AddError("Failed to parse certificate for policy check: " + err.Error())
		return false
	}

	// Parse certificate policies from extensions
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 32}) { // Certificate Policies OID
			policies, err := v.parseCertificatePolicies(ext.Value)
			if err != nil {
				continue
			}

			for _, policy := range policies {
				for _, allowedOid := range allowedOids {
					if policy == allowedOid {
						return true
					}
				}
			}
		}
	}

	return false
}

// VerifySignature verifies ACSP_V2 signature based on reconstructed payload and certificate
func (v *AuthenticationResponseValidator) VerifySignature(authenticationResponse *AuthenticationResponse, payload *DeviceLinkAuthRequest) bool {
	reconstructedPayload := v.BuildACSPV2Payload(authenticationResponse, payload)

	if authenticationResponse.Signature == nil {
		v.result.AddError("Missing signature in response")
		return false
	}

	signatureValue := authenticationResponse.Signature.Value
	certValue := authenticationResponse.Cert.Value
	algorithm := authenticationResponse.Signature.SignatureAlgorithm
	params := authenticationResponse.Signature.SignatureAlgorithmParameters

	if signatureValue == "" || certValue == "" || algorithm == "" || params == nil {
		v.result.AddError("Missing required signature or certificate fields.")
		return false
	}

	if strings.ToLower(algorithm) != "rsassa-pss" {
		v.result.AddError("Unsupported algorithm: " + algorithm)
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(signatureValue)
	if err != nil {
		v.result.AddError("Failed to decode signature: " + err.Error())
		return false
	}

	certPem := v.wrapCertificate(certValue)
	cert, err := v.parseCertificate(certPem)
	if err != nil {
		v.result.AddError("Failed to parse certificate: " + err.Error())
		return false
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		v.result.AddError("Certificate does not contain RSA public key")
		return false
	}

	// Hash the payload
	var hasher crypto.Hash
	switch strings.ToLower(strings.ReplaceAll(params.HashAlgorithm, "-", "")) {
	case "sha256":
		hasher = crypto.SHA256
	case "sha384":
		hasher = crypto.SHA384
	case "sha512":
		hasher = crypto.SHA512
	default:
		v.result.AddError("Unsupported hash algorithm: " + params.HashAlgorithm)
		return false
	}

	hash := hasher.New()
	hash.Write([]byte(reconstructedPayload))
	hashed := hash.Sum(nil)

	// Verify PSS signature
	opts := &rsa.PSSOptions{
		SaltLength: params.SaltLength,
		Hash:       hasher,
	}

	err = rsa.VerifyPSS(publicKey, hasher, hashed, signature, opts)
	if err != nil {
		v.result.AddError("ACSP_V2 signature verification failed: " + err.Error())
		return false
	}

	return true
}

// WithSchemeName sets scheme name for ACSP_V2 payload reconstruction
func (v *AuthenticationResponseValidator) WithSchemeName(name string) *AuthenticationResponseValidator {
	v.schemeName = name
	return v
}

// WithInteractionTypeUsed sets interaction type used for ACSP_V2 payload reconstruction
func (v *AuthenticationResponseValidator) WithInteractionTypeUsed(value string) *AuthenticationResponseValidator {
	v.interactionTypeUsed = value
	return v
}

// WithBrokeredRpName sets brokered RP name for ACSP_V2 payload reconstruction
func (v *AuthenticationResponseValidator) WithBrokeredRpName(name string) *AuthenticationResponseValidator {
	v.brokeredRpName = name
	return v
}

// WithFlowType sets flow type for ACSP_V2 payload reconstruction
func (v *AuthenticationResponseValidator) WithFlowType(value string) *AuthenticationResponseValidator {
	v.flowType = value
	return v
}

// BuildACSPV2Payload reconstructs the exact ACSP_V2 payload string required for signature check
func (v *AuthenticationResponseValidator) BuildACSPV2Payload(authenticationResponse *AuthenticationResponse, payload *DeviceLinkAuthRequest) string {
	schemeName := v.schemeName
	signatureProtocol := string(SignatureProtocolACSP_V2)
	serverRandom := ""
	if authenticationResponse.Signature != nil {
		serverRandom = authenticationResponse.Signature.ServerRandom
	}
	rpChallenge := payload.SignatureProtocolParameters.RPChallenge
	userChallenge := ""
	if authenticationResponse.Signature != nil {
		userChallenge = authenticationResponse.Signature.UserChallenge
	}

	relyingPartyNameBase64 := base64.StdEncoding.EncodeToString([]byte(payload.RelyingPartyName))
	brokeredRpNameBase64 := ""
	if v.brokeredRpName != "" {
		brokeredRpNameBase64 = base64.StdEncoding.EncodeToString([]byte(v.brokeredRpName))
	}

	// Hash the interactions
	hash := sha256.Sum256([]byte(payload.Interactions))
	interactionsBase64 := base64.StdEncoding.EncodeToString(hash[:])

	initialCallbackURL := payload.InitialCallbackURL
	interactionTypeUsed := v.interactionTypeUsed
	flowType := v.flowType

	parts := []string{
		schemeName,
		signatureProtocol,
		serverRandom,
		rpChallenge,
		userChallenge,
		relyingPartyNameBase64,
		brokeredRpNameBase64,
		interactionsBase64,
		interactionTypeUsed,
		initialCallbackURL,
		flowType,
	}

	return strings.Join(parts, "|")
}

// GetTrustedCACertificates returns the list of CA certificate file paths loaded for trust validation
func (v *AuthenticationResponseValidator) GetTrustedCACertificates() []string {
	return v.trustedCACertificates
}

// GetResult returns the result containing validation errors and extracted identity
func (v *AuthenticationResponseValidator) GetResult() *AuthResult {
	return v.result
}

// assertAuthenticationResponseIsCompleteAndValid validates the basic structure of the response
func (v *AuthenticationResponseValidator) assertAuthenticationResponseIsCompleteAndValid(status *AuthenticationResponse) {
	if status.State != "COMPLETE" {
		v.result.AddError("Session is not complete.")
	}

	if status.Result == nil || status.Result.EndResult != string(SmartIdEndResultOK) {
		v.result.AddError("Authentication result is not OK.")
	}

	if status.SignatureProtocol != string(SignatureProtocolACSP_V2) {
		v.result.AddError("Invalid signature protocol. Expected ACSP_V2.")
	}

	if status.Cert == nil || status.Cert.Value == "" || status.Cert.CertificateLevel == "" {
		v.result.AddError("Certificate is missing.")
	}

	if status.Signature == nil || status.Signature.Value == "" {
		v.result.AddError("Signature is missing.")
	}

	if status.Result == nil {
		v.result.AddError("Result is missing.")
	}
}

// isCertificateTrusted checks if a certificate can be verified against the trusted CA store
func (v *AuthenticationResponseValidator) isCertificateTrusted(base64Certificate string) bool {
	certPem := v.wrapCertificate(base64Certificate)
	cert, err := v.parseCertificate(certPem)
	if err != nil {
		v.log("Error parsing certificate: " + err.Error())
		return false
	}

	return v.verifyTrustedCACertificates(cert)
}

// verifyTrustedCACertificates verifies a certificate against the CA store
func (v *AuthenticationResponseValidator) verifyTrustedCACertificates(cert *x509.Certificate) bool {
	if len(v.caStore) == 0 {
		v.result.AddError("No CA certificates loaded for trust verification")
		return false
	}

	// Create CA pool
	caPool := x509.NewCertPool()
	for _, caCert := range v.caStore {
		caPool.AddCert(caCert)
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots: caPool,
	}

	_, err := cert.Verify(opts)
	if err != nil {
		v.result.AddError("Certificate chain verification failed: " + err.Error())
		return false
	}

	v.log("Certificate chain verified successfully.")
	return true
}

// loadCACertificates loads CA certificates from the specified path
func (v *AuthenticationResponseValidator) loadCACertificates(caPath string) error {
	files, err := filepath.Glob(filepath.Join(caPath, "*.pem"))
	if err != nil {
		return err
	}

	crtFiles, err := filepath.Glob(filepath.Join(caPath, "*.crt"))
	if err != nil {
		return err
	}

	files = append(files, crtFiles...)

	for _, file := range files {
		err := v.loadCertificateFile(file)
		if err != nil {
			v.log("Failed to load CA file " + file + ": " + err.Error())
			continue
		}

		if !contains(v.trustedCACertificates, file) {
			v.trustedCACertificates = append(v.trustedCACertificates, file)
		}
	}

	if len(v.caStore) == 0 {
		v.log("No valid CA certificates loaded from " + caPath)
	} else {
		v.log(fmt.Sprintf("Loaded %d CA certificates from %s", len(v.caStore), caPath))
	}

	return nil
}

// loadCertificateFile loads certificates from a single file
func (v *AuthenticationResponseValidator) loadCertificateFile(filename string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	certs := v.splitCertificates(string(data))
	for _, certPEM := range certs {
		cert, err := v.parseCertificate(certPEM)
		if err != nil {
			v.log("Failed to parse CA certificate in " + filename + ": " + err.Error())
			continue
		}

		v.caStore = append(v.caStore, cert)
	}

	return nil
}

// constructAuthenticationIdentity creates an AuthenticationIdentity from the response and certificate
func (v *AuthenticationResponseValidator) constructAuthenticationIdentity(authenticationResponse *AuthenticationResponse, cert *x509.Certificate) *AuthenticationIdentity {
	documentNumber := ""
	if authenticationResponse.Result != nil {
		documentNumber = authenticationResponse.Result.DocumentNumber
	}

	base64Cert := authenticationResponse.Cert.Value
	validFrom := cert.NotBefore
	validTo := cert.NotAfter

	subjectMap := v.getNameMap(cert.Subject)
	givenName := subjectMap["givenName"]
	surName := subjectMap["surname"]
	country := subjectMap["countryName"]
	commonName := subjectMap["commonName"]
	serialNumber := subjectMap["serialNumber"]

	identityNumber := v.extractIdentityNumber(commonName, givenName, surName)
	identityCode := serialNumber
	dateOfBirth := v.extractDateOfBirth(cert)

	return &AuthenticationIdentity{
		GivenName:       givenName,
		SurName:         surName,
		Country:         country,
		IdentityNumber:  identityNumber,
		IdentityCode:    identityCode,
		DocumentNumber:  documentNumber,
		ValidFrom:       validFrom,
		ValidTo:         validTo,
		AuthCertificate: base64Cert,
		DateOfBirth:     dateOfBirth,
	}
}

// wrapCertificate wraps a base64 certificate in PEM format
func (v *AuthenticationResponseValidator) wrapCertificate(base64Cert string) string {
	return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", base64Cert)
}

// parseCertificate parses a PEM-encoded certificate
func (v *AuthenticationResponseValidator) parseCertificate(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

// getNameMap converts x509.Name to a string map
func (v *AuthenticationResponseValidator) getNameMap(name pkix.Name) map[string]string {
	result := make(map[string]string)

	for _, attr := range name.Names {
		key := getOIDName(attr.Type)
		if value, ok := attr.Value.(string); ok {
			result[key] = value
		}
	}

	return result
}

// verifyCertificateExpiry checks if the certificate is still valid
func (v *AuthenticationResponseValidator) verifyCertificateExpiry(cert *x509.Certificate) bool {
	now := time.Now()
	return cert.NotAfter.After(now)
}

// checkSmartIDSchemeIdentification verifies Smart-ID scheme identification requirements
func (v *AuthenticationResponseValidator) checkSmartIDSchemeIdentification(cert *x509.Certificate) bool {
	hasDigitalSignature := false
	hasKeyEncipherment := false
	hasDataEncipherment := false
	hasNewSmartIdEku := false
	hasOldClientAuthEku := false

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		hasDigitalSignature = true
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		hasKeyEncipherment = true
	}
	if cert.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		hasDataEncipherment = true
	}

	// Check extended key usage
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			hasOldClientAuthEku = true
		}
	}

	// Check for Smart-ID specific EKU
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 37}) { // Extended Key Usage OID
			// Parse the extension to look for Smart-ID specific OID
			// This is a simplified check - in production you'd want more robust ASN.1 parsing
			if strings.Contains(string(ext.Value), "1.3.6.1.4.1.62306.5.7.0") {
				hasNewSmartIdEku = true
			}
		}
	}

	// New certs: digitalSignature + Smart-ID EKU
	if hasDigitalSignature && hasNewSmartIdEku {
		return true
	}

	// Older certs: digitalSignature + keyEncipherment + dataEncipherment + id-kp-clientAuth EKU
	return hasDigitalSignature && hasKeyEncipherment && hasDataEncipherment && hasOldClientAuthEku
}

// extractDateOfBirth extracts date of birth from certificate extensions
func (v *AuthenticationResponseValidator) extractDateOfBirth(cert *x509.Certificate) string {
	// This is a simplified implementation
	// In production, you'd want proper ASN.1 parsing for Subject Directory Attributes
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 9}) { // Subject Directory Attributes OID
			// Parse the extension to extract date of birth
			// This would require proper ASN.1 parsing in production
			return ""
		}
	}
	return ""
}

// extractIdentityNumber extracts identity number from common name
func (v *AuthenticationResponseValidator) extractIdentityNumber(commonName, givenName, surName string) string {
	parts := strings.Split(commonName, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != givenName && part != surName && part != "" {
			return part
		}
	}
	return ""
}

// isEqualOrAbove checks if actual certificate level meets or exceeds required level
func (v *AuthenticationResponseValidator) isEqualOrAbove(actual, required CertificateLevel) bool {
	if required == "" {
		return true
	}

	actualLevel, ok := CertificationLevelOrder[actual]
	if !ok {
		return false
	}

	requiredLevel, ok := CertificationLevelOrder[required]
	if !ok {
		return false
	}

	return actualLevel >= requiredLevel
}

// splitCertificates splits a PEM file containing multiple certificates
func (v *AuthenticationResponseValidator) splitCertificates(pemData string) []string {
	var certs []string
	re := regexp.MustCompile(`-----BEGIN CERTIFICATE-----\n([\s\S]*?)\n-----END CERTIFICATE-----`)
	matches := re.FindAllStringSubmatch(pemData, -1)

	for _, match := range matches {
		if len(match) > 1 {
			cert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", match[1])
			certs = append(certs, cert)
		}
	}

	return certs
}

// parseCertificatePolicies parses certificate policy OIDs from extension value
func (v *AuthenticationResponseValidator) parseCertificatePolicies(extValue []byte) ([]string, error) {
	var policies []string

	// This is a simplified implementation
	// In production, you'd want proper ASN.1 parsing for certificate policies
	var seq asn1.RawValue
	_, err := asn1.Unmarshal(extValue, &seq)
	if err != nil {
		return nil, err
	}

	// Parse the sequence of policy information
	// This would require more sophisticated ASN.1 parsing in production
	return policies, nil
}

// log outputs debug messages if debug mode is enabled
func (v *AuthenticationResponseValidator) log(message string) {
	if v.debug {
		fmt.Printf("[AuthValidator] %s\n", message)
	}
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
