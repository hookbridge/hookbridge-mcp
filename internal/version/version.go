package version

var Version = "dev"

func UserAgent(agent string) string {
	ua := "hb-mcp/" + Version
	if agent != "" {
		ua += "; agent=" + agent
	}
	return ua
}
