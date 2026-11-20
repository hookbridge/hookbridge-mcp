# hookbridge-mcp

Shared MCP server tools for Hookbridge, used by the `hb` CLI and the hosted MCP server.

## Usage

```go
srv := hbmcp.NewServer(hbmcp.Options{
	NewClient: newClient, // returns a *hookbridge.Client per tool call
	Version:   version,
	Auth:      hbmcp.AuthOAuth, // or hbmcp.AuthAPIKey
	Projects:  lister,         // from hbmcp.NewHTTPProjectLister, OAuth only
})
```

`NewServer` panics on invalid options.

## Tests

```sh
go test -race ./...
```
