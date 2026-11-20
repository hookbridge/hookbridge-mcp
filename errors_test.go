package hbmcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	hookbridge "github.com/hookbridge/hookbridge-go/v2"
)

func apiErr(status int, code, msg string) *hookbridge.APIError {
	return &hookbridge.APIError{StatusCode: status, Code: code, Message: msg, RequestID: "req_1"}
}

func TestFriendlyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		auth AuthMode
		want string
		not  string
	}{
		{"not found", &hookbridge.NotFoundError{APIError: apiErr(404, "NOT_FOUND", "x")}, AuthOAuth, "don't have access", ""},
		{"auth oauth", &hookbridge.AuthenticationError{APIError: apiErr(401, "UNAUTHORIZED", "x")}, AuthOAuth, "hb login", ""},
		{"auth key", &hookbridge.AuthenticationError{APIError: apiErr(401, "UNAUTHORIZED", "x")}, AuthAPIKey, "API key", "hb login"},
		{"forbidden passes message", apiErr(403, "FORBIDDEN", "Viewers cannot do that"), AuthOAuth, "Viewers cannot do that", ""},
		{"rate limit", &hookbridge.RateLimitError{APIError: apiErr(429, "RATE_LIMITED", "x")}, AuthOAuth, "rate limited", ""},
		{"validation", &hookbridge.ValidationError{APIError: apiErr(400, "VALIDATION_ERROR", "bad window")}, AuthOAuth, "bad window", ""},
		{"server", apiErr(502, "BAD_GATEWAY", "upstream"), AuthOAuth, "server error", "upstream"},
		{"timeout", &hookbridge.TimeoutError{Err: context.DeadlineExceeded}, AuthOAuth, "timed out", ""},
		{"network", &hookbridge.NetworkError{Err: errors.New("dial tcp 10.0.0.1:443: refused")}, AuthOAuth, "reach Hookbridge", "10.0.0.1"},
		{"wrapped", fmt.Errorf("wrap: %w", &hookbridge.NotFoundError{APIError: apiErr(404, "NOT_FOUND", "x")}), AuthOAuth, "don't have access", ""},
		{"unknown", errors.New("secret internal detail"), AuthOAuth, "Unexpected", "secret"},
		{"user error", userErrorf("limit must be small"), AuthOAuth, "limit must be small", ""},
		{"message redacted", apiErr(403, "FORBIDDEN", "see https://u:hunter2@example.com/x?token=abc123"), AuthOAuth, "[redacted]", "hunter2"},
		{"long message capped", apiErr(403, "FORBIDDEN", strings.Repeat("z", 5000)), AuthOAuth, "zzz", strings.Repeat("z", 1000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := friendlyError(tt.err, tt.auth)
			if !strings.Contains(got, tt.want) {
				t.Errorf("got %q, want containing %q", got, tt.want)
			}
			if tt.not != "" && strings.Contains(got, tt.not) {
				t.Errorf("got %q, must not contain %q", got, tt.not)
			}
		})
	}
}
