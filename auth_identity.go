package smartid

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// AuthenticationIdentity represents an authenticated user's identity extracted from a Smart-ID certificate
type AuthenticationIdentity struct {
	GivenName       string
	SurName         string
	IdentityCode    string
	IdentityNumber  string
	Country         string
	AuthCertificate string
	DocumentNumber  string
	ValidFrom       time.Time
	ValidTo         time.Time
	DateOfBirth     string
}

// NewAuthenticationIdentity creates a new AuthenticationIdentity instance
func NewAuthenticationIdentity() *AuthenticationIdentity {
	return &AuthenticationIdentity{}
}

// GetGivenName returns the given name
func (a *AuthenticationIdentity) GetGivenName() string {
	return a.GivenName
}

// GetSurName returns the surname
func (a *AuthenticationIdentity) GetSurName() string {
	return a.SurName
}

// GetIdentityCode returns the identity code
func (a *AuthenticationIdentity) GetIdentityCode() string {
	return a.IdentityCode
}

// GetIdentityNumber returns the identity number
func (a *AuthenticationIdentity) GetIdentityNumber() string {
	return a.IdentityNumber
}

// GetCountry returns the country
func (a *AuthenticationIdentity) GetCountry() string {
	return a.Country
}

// GetDocumentNumber returns the document number
func (a *AuthenticationIdentity) GetDocumentNumber() string {
	return a.DocumentNumber
}

// GetValidFrom returns certificate validity start time
func (a *AuthenticationIdentity) GetValidFrom() time.Time {
	return a.ValidFrom
}

// GetValidTo returns certificate validity end time
func (a *AuthenticationIdentity) GetValidTo() time.Time {
	return a.ValidTo
}

// GetDateOfBirth returns the date of birth
func (a *AuthenticationIdentity) GetDateOfBirth() string {
	return a.DateOfBirth
}

// GetCertificate returns the raw certificate (Base64)
func (a *AuthenticationIdentity) GetCertificate() string {
	return a.AuthCertificate
}

// GetPemCertificate returns the certificate in PEM format
func (a *AuthenticationIdentity) GetPemCertificate() string {
	return a.wrapCertificate(a.AuthCertificate)
}

// GetParsedCertificate returns parsed certificate information
func (a *AuthenticationIdentity) GetParsedCertificate() map[string]interface{} {
	cert := a.GetRawCertificate()
	if cert == nil {
		return nil
	}

	result := make(map[string]interface{})

	// Parse subject
	subject := make(map[string]string)
	for _, name := range cert.Subject.Names {
		if name.Type != nil {
			key := getOIDName(name.Type)
			if value, ok := name.Value.(string); ok {
				subject[key] = value
			}
		}
	}
	result["subject"] = subject

	// Parse issuer
	issuer := make(map[string]string)
	for _, name := range cert.Issuer.Names {
		if name.Type != nil {
			key := getOIDName(name.Type)
			if value, ok := name.Value.(string); ok {
				issuer[key] = value
			}
		}
	}
	result["issuer"] = issuer

	// Add other certificate fields
	result["serialNumber"] = cert.SerialNumber.String()
	result["validFrom"] = cert.NotBefore.Format(time.RFC3339)
	result["validTo"] = cert.NotAfter.Format(time.RFC3339)

	// Parse extensions
	extensions := make(map[string]interface{})
	for _, ext := range cert.Extensions {
		if ext.Id != nil {
			extensions[ext.Id.String()] = ext.Value
		}
	}
	result["extensions"] = extensions

	return result
}

// GetRawCertificate returns the raw certificate object
func (a *AuthenticationIdentity) GetRawCertificate() *x509.Certificate {
	pemCert := a.GetPemCertificate()
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}

	return cert
}

// wrapCertificate wraps a base64 certificate string in PEM format
func (a *AuthenticationIdentity) wrapCertificate(certificateValue string) string {
	// Remove existing PEM headers if present
	cleaned := strings.ReplaceAll(certificateValue, "-----BEGIN CERTIFICATE-----", "")
	cleaned = strings.ReplaceAll(cleaned, "-----END CERTIFICATE-----", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")

	// Split into 64-character lines
	var lines []string
	for i := 0; i < len(cleaned); i += 64 {
		end := i + 64
		if end > len(cleaned) {
			end = len(cleaned)
		}
		lines = append(lines, cleaned[i:end])
	}

	return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
		strings.Join(lines, "\n"))
}

// getOIDName converts an OID to a human-readable name
func getOIDName(oid []int) string {
	oidStr := fmt.Sprintf("%v", oid)
	switch oidStr {
	case "[2 5 4 3]":
		return "commonName"
	case "[2 5 4 4]":
		return "surname"
	case "[2 5 4 42]":
		return "givenName"
	case "[2 5 4 6]":
		return "countryName"
	case "[2 5 4 5]":
		return "serialNumber"
	case "[2 5 4 7]":
		return "localityName"
	case "[2 5 4 8]":
		return "stateOrProvinceName"
	case "[2 5 4 10]":
		return "organizationName"
	case "[2 5 4 11]":
		return "organizationalUnitName"
	default:
		return strings.Trim(oidStr, "[]")
	}
}
