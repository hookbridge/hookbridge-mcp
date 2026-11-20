package hbmcp

import (
	"context"
	"errors"
	"unicode/utf8"

	hookbridge "github.com/hookbridge/hookbridge-go/v2"
	"github.com/hookbridge/hookbridge-mcp/internal/redact"
)

const maxErrorMessage = 300

// friendlyError turns an error into a short message for the agent. It never
// includes tokens, headers or URLs; API text is redacted and capped.
func friendlyError(err error, auth AuthMode) string {
	var (
		ue      *userError
		auth401 *hookbridge.AuthenticationError
		nf      *hookbridge.NotFoundError
		val     *hookbridge.ValidationError
		rl      *hookbridge.RateLimitError
		rpl     *hookbridge.ReplayLimitError
		idem    *hookbridge.IdempotencyError
		to      *hookbridge.TimeoutError
		net     *hookbridge.NetworkError
		api     *hookbridge.APIError
	)
	switch {
	case errors.As(err, &ue):
		return ue.msg
	case errors.As(err, &auth401):
		if auth == AuthAPIKey {
			return "Hookbridge rejected the API key. Check that it is valid and not revoked."
		}
		return "Not signed in, or the token expired. Run `hb login` and try again."
	case errors.As(err, &nf):
		return "Not found, or you don't have access to this project."
	case errors.As(err, &val):
		return "Hookbridge rejected the request: " + apiMessage(val.APIError)
	case errors.As(err, &rl):
		return "Hookbridge says you are rate limited. Try again in a bit."
	case errors.As(err, &rpl):
		return "Replay limit reached: " + apiMessage(rpl.APIError)
	case errors.As(err, &idem):
		return "Conflict: " + apiMessage(idem.APIError)
	case errors.As(err, &to), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "The request to Hookbridge timed out. Try again."
	case errors.As(err, &net):
		return "Could not reach Hookbridge. Check the network and try again."
	case errors.As(err, &api):
		switch {
		case api.Code == badResponseCode:
			return "Hookbridge returned an unexpected response. Try again in a bit."
		case api.StatusCode == 403:
			return "Permission denied: " + apiMessage(api)
		case api.StatusCode >= 500:
			return "Hookbridge had a server error. Try again in a bit."
		}
		return "Hookbridge returned an error: " + apiMessage(api)
	}
	return "Unexpected error talking to Hookbridge."
}

func apiMessage(e *hookbridge.APIError) string {
	msg := redact.Text(e.Message)
	if len(msg) > maxErrorMessage {
		cut := maxErrorMessage
		for cut > 0 && !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut]
	}
	return msg
}
