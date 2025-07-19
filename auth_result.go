package smartid

// AuthResult represents the result of an authentication validation operation
type AuthResult struct {
	valid    bool
	errors   []string
	identity *AuthenticationIdentity
}

// NewAuthResult creates a new AuthResult instance
func NewAuthResult() *AuthResult {
	return &AuthResult{
		valid:  true,
		errors: make([]string, 0),
	}
}

// IsValid returns whether the authentication result is valid
func (r *AuthResult) IsValid() bool {
	return r.valid
}

// SetValid sets the validity of the authentication result
func (r *AuthResult) SetValid(valid bool) *AuthResult {
	r.valid = valid
	return r
}

// AddError adds an error to the result and marks it as invalid
func (r *AuthResult) AddError(error string) *AuthResult {
	r.errors = append(r.errors, error)
	r.valid = false
	return r
}

// GetErrors returns a copy of all errors
func (r *AuthResult) GetErrors() []string {
	errors := make([]string, len(r.errors))
	copy(errors, r.errors)
	return errors
}

// GetIdentity returns the authentication identity if available
func (r *AuthResult) GetIdentity() *AuthenticationIdentity {
	return r.identity
}

// SetIdentity sets the authentication identity
func (r *AuthResult) SetIdentity(identity *AuthenticationIdentity) *AuthResult {
	r.identity = identity
	return r
}

// HasError returns whether there are any errors
func (r *AuthResult) HasError() bool {
	return len(r.errors) > 0
}
