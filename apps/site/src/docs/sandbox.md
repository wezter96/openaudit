Nothing on openaudit.se holds data of yours, so there is no production system to break. The public MCP endpoint is read-only, and everything that runs an audit runs on your own machine, which makes it your sandbox.

## Public MCP endpoint

`https://openaudit.se/mcp` is a read-only MCP server over Streamable HTTP with the auditor catalogue, playbooks, docs search, config schema and install instructions. It needs no account or key, keeps nothing you send and cannot run audits, so you can point any MCP client or test harness at it.

```sh
# List the tools
curl -s https://openaudit.se/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Call one
curl -s https://openaudit.se/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_auditors","arguments":{"category":"accessibility"}}}'
```

In the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) (`npx @modelcontextprotocol/inspector`), choose Streamable HTTP and enter the same URL. Its [server card](/.well-known/mcp/server-card.json) describes it for registries and clients.

## Your own MCP server

To run audits, start the full server on your machine. Over stdio it needs no credentials. Over HTTP it binds to loopback, accepts only targets inside the folders you pass with `--root`, and generates a bearer token for you:

```sh
bunx @openaudit/cli mcp                                  # stdio, for Claude Code, Cursor or Codex
bunx @openaudit/cli mcp --http --root ~/code/playground  # http://127.0.0.1:7337/mcp
```

[MCP over HTTP](/docs/agents/#mcp-over-http) lists every flag.

## Your own HTTP API

openaudit.se does not host the [HTTP API](/docs/api/), so a server you start is the test environment, and nothing it does reaches anyone else's data. From a clone of the repository:

```sh
bun install
CORS_ORIGIN=http://localhost:3001 bun run dev:server   # http://localhost:3000
curl -s http://localhost:3000/api-reference/healthCheck
curl -s http://localhost:3000/api-reference/auditors
```

URL audits refuse private and loopback addresses. To try them against an app running on your machine, start the server with `ALLOW_PRIVATE_TARGETS=true` and don't expose it to other machines.

## Safe targets

- **Your own code.** An audit reads the target and changes nothing in it. Auditors that run project code, or are slow, costly or traffic-heavy, only run when you select them with `--only`.
- **No network.** `--offline` allows no network access except to the target itself.
- **Isolated.** The Docker image keeps the scanners off your machine:

  ```sh
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" -w /src ghcr.io/wezter96/openaudit .
  ```

- **Websites.** By default a URL audit sends a small number of GET and HEAD requests. Point it at sites you own or may test; a local dev server or a preview deployment makes a good sandbox.
- **Agent playbooks.** Give the agent test accounts and test data, never real ones. See [Responsible use](/docs/safety/#responsible-use).

## Verified badge

The [badge API](/badge/) writes to openaudit.se's own database and has no test mode. To try it, register a throwaway public repository, then remove the badge with its manage token. Removing it deletes its scans and reports, and registrations that are never verified are deleted after seven days.
