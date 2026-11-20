package version

import "strings"

var Version = "dev"

// MaxAgentLen caps the agent name so the whole header stays far below the
// API's 200-byte column.
const MaxAgentLen = 64

// UserAgent returns the client identifier sent to Hookbridge. agent is
// user-controlled (the MCP clientInfo name), so it is reduced to printable
// ASCII without ';', '=' or ',' (so it cannot fake extra key=value pairs) and
// truncated.
func UserAgent(agent string) string {
	return UserAgentFor(Version, agent)
}

// UserAgentFor is UserAgent for an explicit tools version.
func UserAgentFor(ver, agent string) string {
	return "hb-mcp/" + ver + "; agent=" + cleanAgent(agent)
}

func cleanAgent(agent string) string {
	var b strings.Builder
	for i := 0; i < len(agent); i++ {
		if c := agent[i]; c >= 0x20 && c <= 0x7e && c != ';' && c != '=' && c != ',' {
			b.WriteByte(c)
		}
	}
	s := strings.TrimSpace(b.String())
	if len(s) > MaxAgentLen {
		s = strings.TrimSpace(s[:MaxAgentLen])
	}
	if s == "" {
		return "unknown"
	}
	return s
}
