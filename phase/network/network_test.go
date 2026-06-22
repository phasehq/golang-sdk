package network

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestFormatHTTPErrorPreservesRetryAfter(t *testing.T) {
	headers := http.Header{"Retry-After": []string{"7"}}

	err := formatHTTPError(http.StatusTooManyRequests, nil, headers)
	var rateErr *RateLimitError
	if !errors.As(err, &rateErr) {
		t.Fatalf("formatHTTPError() = %T, want *RateLimitError", err)
	}
	if rateErr.RetryAfter != 7*time.Second {
		t.Fatalf("RetryAfter = %s, want 7s", rateErr.RetryAfter)
	}
}

func TestFormatHTTPErrorPreservesRetryAfterForAPIError(t *testing.T) {
	headers := http.Header{"Retry-After": []string{"3"}}

	err := formatHTTPError(http.StatusServiceUnavailable, []byte(`{"error":"try later"}`), headers)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("formatHTTPError() = %T, want *APIError", err)
	}
	if apiErr.RetryAfter != 3*time.Second {
		t.Fatalf("RetryAfter = %s, want 3s", apiErr.RetryAfter)
	}
}
