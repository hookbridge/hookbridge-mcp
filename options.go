// Package hbmcp is the Hookbridge MCP tool server, shared by the local
// `hb mcp` command and the hosted endpoint.
package hbmcp

import (
	"context"
	"fmt"

	hookbridge "github.com/hookbridge/hookbridge-go/v2"
)

// AuthMode says how the connection authenticates to Hookbridge.
type AuthMode int

const (
	// AuthOAuth is an OAuth access token. Every tool call must name a project.
	AuthOAuth AuthMode = iota + 1
	// AuthAPIKey is a project API key. The key already fixes the project.
	AuthAPIKey
)

// Options configures NewServer.
type Options struct {
	// NewClient returns the Hookbridge client for one tool call. Hosted mode
	// builds a client per call with a freshly minted token.
	NewClient func(ctx context.Context) (*hookbridge.Client, error)
	// Version is the tools version, reported in the client-name header.
	Version string
	Auth    AuthMode
	// APIKeyProjectID is the API key's project, if the caller knows it. Only
	// valid with AuthAPIKey.
	APIKeyProjectID string
	// Projects backs list_projects. Required with AuthOAuth.
	Projects ProjectLister
}

func (o Options) validate() error {
	switch o.Auth {
	case AuthOAuth:
		if o.Projects == nil {
			return fmt.Errorf("options: Projects is required with AuthOAuth")
		}
		if o.APIKeyProjectID != "" {
			return fmt.Errorf("options: APIKeyProjectID is only valid with AuthAPIKey")
		}
	case AuthAPIKey:
		if o.APIKeyProjectID != "" && !uuidRe.MatchString(o.APIKeyProjectID) {
			return fmt.Errorf("options: APIKeyProjectID is not a valid UUID")
		}
	default:
		return fmt.Errorf("options: Auth must be AuthOAuth or AuthAPIKey")
	}
	if o.NewClient == nil {
		return fmt.Errorf("options: NewClient is required")
	}
	return nil
}
