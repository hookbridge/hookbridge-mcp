package version

import "testing"

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name  string
		agent string
		want  string
	}{
		{"no agent", "", "hb-mcp/dev"},
		{"with agent", "claude-desktop", "hb-mcp/dev; agent=claude-desktop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UserAgent(tt.agent); got != tt.want {
				t.Errorf("UserAgent(%q) = %q, want %q", tt.agent, got, tt.want)
			}
		})
	}
}
