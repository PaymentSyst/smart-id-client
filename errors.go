package smartid

import "fmt"

// SmartIdError is the base error type for Smart-ID operations
type SmartIdError struct {
	Message string
}

func (e SmartIdError) Error() string {
	return e.Message
}

// NewSmartIdError creates a new SmartIdError
func NewSmartIdError(message string) *SmartIdError {
	return &SmartIdError{Message: message}
}

// SmartIdUserRefusedError represents an error when the user refuses the Smart-ID operation
type SmartIdUserRefusedError struct {
	SmartIdError
}

// NewSmartIdUserRefusedError creates a new SmartIdUserRefusedError
func NewSmartIdUserRefusedError() *SmartIdUserRefusedError {
	return &SmartIdUserRefusedError{
		SmartIdError: SmartIdError{Message: "User refused Smart-ID operation."},
	}
}

// SmartIdTimeoutError represents an error when the Smart-ID session times out
type SmartIdTimeoutError struct {
	SmartIdError
}

// NewSmartIdTimeoutError creates a new SmartIdTimeoutError
func NewSmartIdTimeoutError() *SmartIdTimeoutError {
	return &SmartIdTimeoutError{
		SmartIdError: SmartIdError{Message: "Smart-ID session timed out."},
	}
}

// SmartIdSessionFailedError represents an error when the Smart-ID session fails
type SmartIdSessionFailedError struct {
	SmartIdError
	EndResult string
}

// NewSmartIdSessionFailedError creates a new SmartIdSessionFailedError
func NewSmartIdSessionFailedError(endResult string) *SmartIdSessionFailedError {
	return &SmartIdSessionFailedError{
		SmartIdError: SmartIdError{Message: fmt.Sprintf("Smart-ID session failed: %s", endResult)},
		EndResult:    endResult,
	}
}
