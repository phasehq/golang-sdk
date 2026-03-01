package network

import "fmt"

// NetworkError represents transport-level errors: DNS, connection refused, timeout.
type NetworkError struct {
	Kind   string // "dns", "connection", "timeout", "unknown"
	Host   string // target host, when available (e.g. DNS errors)
	Detail string // underlying error message
}

func (e *NetworkError) Error() string {
	switch e.Kind {
	case "dns":
		return fmt.Sprintf("network error: could not resolve host '%s'", e.Host)
	case "connection":
		return "network error: could not connect to host"
	case "timeout":
		return "network error: request timed out"
	default:
		return fmt.Sprintf("network error: %s", e.Detail)
	}
}

// SSLError represents TLS/certificate errors.
type SSLError struct {
	Detail string
}

func (e *SSLError) Error() string {
	return fmt.Sprintf("ssl error: %s", e.Detail)
}

// AuthorizationError represents HTTP 403 Forbidden responses.
type AuthorizationError struct {
	Detail string // server-provided detail, may be empty
}

func (e *AuthorizationError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("not authorized: %s", e.Detail)
	}
	return "not authorized"
}

// RateLimitError represents HTTP 429 Too Many Requests.
type RateLimitError struct{}

func (e *RateLimitError) Error() string {
	return "rate limited"
}

// APIError represents non-200 HTTP responses (excluding 403 and 429).
type APIError struct {
	StatusCode int
	Detail     string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("request failed (HTTP %d): %s", e.StatusCode, e.Detail)
	}
	return fmt.Sprintf("request failed with status code %d", e.StatusCode)
}
