package version

import (
	"strings"
	"testing"
)

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name  string
		agent string
		want  string
	}{
		{"empty agent", "", "hb-mcp/dev; agent=unknown"},
		{"with agent", "claude-desktop", "hb-mcp/dev; agent=claude-desktop"},
		{"control chars stripped", "evil\r\nX-Injected: 1\x00", "hb-mcp/dev; agent=evilX-Injected: 1"},
		{"non-ascii stripped", "clïent→名", "hb-mcp/dev; agent=clent"},
		{"only junk", "\r\n\x7f→", "hb-mcp/dev; agent=unknown"},
		{"cannot fake pairs", "x; agent=admin, role=root", "hb-mcp/dev; agent=x agentadmin roleroot"},
		{"trimmed", "  spaced  ", "hb-mcp/dev; agent=spaced"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UserAgent(tt.agent); got != tt.want {
				t.Errorf("UserAgent(%q) = %q, want %q", tt.agent, got, tt.want)
			}
		})
	}
}

func TestUserAgentCapsLength(t *testing.T) {
	got := UserAgent(strings.Repeat("a", 5000))
	want := "hb-mcp/dev; agent=" + strings.Repeat("a", MaxAgentLen)
	if got != want {
		t.Errorf("got %d bytes, want %d", len(got), len(want))
	}
}
