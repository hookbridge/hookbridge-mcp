package hbmcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	hookbridge "github.com/hookbridge/hookbridge-go/v2"
)

const (
	maxProjectsResponse = 1 << 20
	projectsTimeout     = 30 * time.Second
)

// Project is one project the signed-in user can access, as the API returns
// it. Name is user-controlled and must not reach the agent unwrapped.
type Project struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Status           string `json:"status"`
	Role             string `json:"role,omitempty"`
	RateLimitDefault int    `json:"rate_limit_default"`
	CreatedAt        string `json:"created_at"`
}

// ProjectLister lists the caller's projects. clientName is the value for the
// X-Hookbridge-Client header.
type ProjectLister interface {
	ListProjects(ctx context.Context, clientName string) ([]Project, error)
}

type httpProjectLister struct {
	url     string
	tokens  hookbridge.TokenSource
	hc      *http.Client
	timeout time.Duration
}

// NewHTTPProjectLister calls GET /v1/projects, which hookbridge-go does not
// wrap. baseURL must be HTTPS unless its host is loopback. A nil hc gets a
// default client with a timeout. Redirects are never followed.
func NewHTTPProjectLister(baseURL string, tokens hookbridge.TokenSource, hc *http.Client) (ProjectLister, error) {
	if tokens == nil {
		return nil, fmt.Errorf("token source is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid base URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
		return nil, fmt.Errorf("base URL must be https unless the host is loopback")
	}
	client := &http.Client{Timeout: projectsTimeout}
	if hc != nil {
		c := *hc
		client = &c
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &httpProjectLister{url: strings.TrimSuffix(baseURL, "/") + "/v1/projects", tokens: tokens, hc: client, timeout: projectsTimeout}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (l *httpProjectLister) ListProjects(ctx context.Context, clientName string) ([]Project, error) {
	ctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	token, err := l.tokens.Token(ctx)
	if err != nil && ctx.Err() != nil {
		return nil, &hookbridge.TimeoutError{Err: ctx.Err()}
	}
	if err != nil || token == "" || hasControl(token) {
		return nil, &hookbridge.AuthenticationError{APIError: &hookbridge.APIError{
			Code: "TOKEN_SOURCE_ERROR", Message: "failed to get access token", StatusCode: http.StatusUnauthorized,
		}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.url, nil)
	if err != nil {
		return nil, &hookbridge.NetworkError{Err: fmt.Errorf("build request")}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if clientName != "" && !hasControl(clientName) {
		req.Header.Set("User-Agent", clientName)
		req.Header.Set("X-Hookbridge-Client", clientName)
	}

	resp, err := l.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &hookbridge.TimeoutError{Err: ctx.Err()}
		}
		return nil, &hookbridge.NetworkError{Err: fmt.Errorf("request failed")}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProjectsResponse+1))
	if err != nil {
		return nil, &hookbridge.NetworkError{Err: fmt.Errorf("read response")}
	}
	if len(body) > maxProjectsResponse {
		return nil, badResponse()
	}

	if resp.StatusCode != http.StatusOK {
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(body, &env)
		return nil, statusError(resp.StatusCode, env.Error.Code, env.Error.Message)
	}
	var out struct {
		Data []Project `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, badResponse()
	}
	return out.Data, nil
}

const badResponseCode = "BAD_RESPONSE"

func badResponse() error {
	return &hookbridge.APIError{Code: badResponseCode, Message: "unexpected response", StatusCode: http.StatusBadGateway}
}

func statusError(status int, code, msg string) error {
	base := &hookbridge.APIError{StatusCode: status, Code: code, Message: msg}
	switch status {
	case http.StatusUnauthorized:
		return &hookbridge.AuthenticationError{APIError: base}
	case http.StatusNotFound:
		return &hookbridge.NotFoundError{APIError: base}
	case http.StatusBadRequest:
		return &hookbridge.ValidationError{APIError: base}
	case http.StatusTooManyRequests:
		return &hookbridge.RateLimitError{APIError: base}
	}
	return base
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}
