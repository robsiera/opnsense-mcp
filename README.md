# OPNsense MCP

A safety-focused remote Model Context Protocol server for OPNsense's MVC API. It exposes stateful Streamable HTTP for remote agents, uses the API's native HTTP Basic authentication upstream, and fails closed when it cannot determine whether an OPNsense command is read-only.

One MCP process can manage one or more OPNsense firewalls. Targets and API credentials stay in the server environment or a local JSON config file; agents never supply firewall URLs or credentials. Agents authenticate to MCP with a separate bearer token (HTTP) and select a firewall with an optional `instance` tool argument. Mutation plan tokens are bound to the instance they were created for.

## Architecture

```text
Remote agent --HTTPS + MCP bearer token--> OPNsense MCP --HTTPS + API key/secret--> OPNsense
```

The MCP endpoint uses the current Streamable HTTP transport at `/mcp`. Sessions are stateful so one-time mutation plans remain bound to the agent's MCP session. Sessions are capped, expire after inactivity, and authenticate on every HTTP request.

The built-in HTTP listener is intended to sit behind a TLS reverse proxy, ingress controller, VPN, or private overlay. Do not expose its plain HTTP port directly to an untrusted network.

## OPNsense API Model

OPNsense routes API requests as:

```text
/api/<module>/<controller>/<command>/<parameter...>
```

The important behaviors for automation are:

- API keys use HTTP Basic authentication: key as username, secret as password.
- Access is still constrained by the key owner's OPNsense ACL privileges.
- Requests and most responses are JSON. Downloads and streams may not be.
- `GET` and `POST` do not map cleanly to safe and unsafe operations. Some reads use `POST`, and some mutations use `GET`.
- Mutable model controllers commonly expose `get`, `search`, `add`, `set`, `del`, and `toggle` operations.
- Array model records use UUIDs. A `get` without a UUID often returns a blank record populated with defaults.
- A successful model mutation usually writes staged configuration. A separate `apply` or `reconfigure` activates it.
- Model writes return values such as `{"result":"saved"}` or `{"result":"failed","validations":...}`; HTTP 200 alone does not prove semantic success.
- OPNsense configuration locking, model validation, revision context, and ACL checks happen server-side and should not be bypassed.

Official references:

- <https://docs.opnsense.org/development/api.html>
- <https://docs.opnsense.org/development/how-tos/api.html>
- <https://docs.opnsense.org/development/architecture.html>
- <https://docs.opnsense.org/development/frontend/controller.html>
- <https://docs.opnsense.org/development/frontend/models_fieldtypes.html>
- <https://github.com/opnsense/core>
- <https://github.com/opnsense/plugins>

## Safety Model

`opnsense_request` accepts only commands classified as reads. Classification is based on the command, not its HTTP method.

Mutations use two tools:

- `opnsense_plan_change` reports the exact request and its risk without contacting OPNsense.
- `opnsense_execute_change` requires a matching one-time token that expires after five minutes.

Risk classes distinguish staged writes, activation, disruptive service or firmware operations, and catastrophic reset/restore operations. Unknown commands fail closed as mutations.

The write mode is controlled outside the agent:

- `disabled` permits reads only.
- `plan` permits mutation analysis but never creates an execution token.
- `enabled` permits execution with a matching token.

Use a dedicated OPNsense user and grant only the effective privileges required by the intended tools. For read-only deployments, also grant `System: Deny config write` (`user-config-readonly`) in OPNsense.

## Curated Read Tools

The guarded generic client is supplemented by fixed read-only tools for common operational tasks:

- `opnsense_get_firewall_logs` reads structured packet-filter events.
- `opnsense_get_logs` reads bounded pages from core and service logs, including system, configd, gateways, VPN, DNS, DHCP, IDS, routing, and web UI logs.
- `opnsense_list_firewall_rules` reads filter rules visible to the automation API.
- `opnsense_list_nat_rules` reads destination, source, one-to-one, or NPT rules.
- `opnsense_get_route_table` reads either the live kernel routing table or configured static routes.

These tools call fixed query endpoints directly. They cannot select mutating sibling actions such as clearing logs, flushing states, changing rules, or applying configuration. Results remain subject to the API user's OPNsense ACL privileges.

## Setup

### Active diagnostics with writes disabled

`OPNSENSE_WRITE_MODE=disabled` also allows these narrowly scoped tools:

- `opnsense_ping`: IPv4/IPv6 ping, 1–10 seconds, one-second interval, maximum 1400-byte payload. Creates a temporary job, collects statistics, then stops and removes only that job.
- `opnsense_traceroute`: IPv4/IPv6 UDP or ICMP traceroute.
- `opnsense_probe_port`: one TCP connectivity test, without fetching remote banners.

These tools generate network traffic and temporary runtime state, so they are marked non-destructive but **not** read-only in MCP annotations. They do not save firewall configuration or enable arbitrary `set`, `start`, `stop`, or `remove` calls through the generic request tool. Only one active diagnostic runs per OPNsense instance at a time.

For example, call `opnsense_ping` with `{"host":"1.1.1.1","durationSeconds":3}` while configuration writes remain disabled.

**OPNsense permissions:** its ping, traceroute, and portprobe models use `:memory:` storage, but their controllers still call `throwReadOnly()`. Accounts with `System: Deny config write` (`user-config-readonly`) may therefore be denied active diagnostics even though no configuration is persisted. Our write-mode setting does not override that check. A diagnostics-only account needs the specific ping/traceroute/portprobe ACL privileges; avoid granting broad configuration privileges. Use separate monitoring and diagnostic accounts/deployments if needed.

Ping statistics are collected while the job is running: OPNsense's job-list endpoint requests a statistics snapshot, so stopping first would leave counters null. Collection allows up to one additional second for the snapshot to appear. Null counters return an explicit error, not a claim of success or packet loss. The returned job status describes the snapshot before cleanup; stop/remove still run before the tool returns.

Ping cleanup is best-effort when OPNsense becomes unreachable: failures return the job UUID and a warning rather than silently claiming success. Process termination can also leave a temporary job behind (upstream ping has a one-day hard limit). Traceroute and TCP probe limits are controlled by OPNsense; an HTTP timeout does not cancel the backend command. Run probes only against networks you are authorized to diagnose.

```sh
npm install
npm run build
```

Configure the environment using `.env.example` as a reference. Environment files are not loaded automatically and are ignored by Git. Generate a separate MCP token with `openssl rand -hex 32`; do not reuse an OPNsense API credential.

Prefer a publicly trusted certificate or set `OPNSENSE_CA_FILE` to the private CA certificate. `OPNSENSE_TLS_VERIFY=false` exists for isolated development only.

Run the remote server on loopback for a local TLS reverse proxy:

```sh
OPNSENSE_URL=https://firewall.example \
OPNSENSE_API_KEY=... \
OPNSENSE_API_SECRET=... \
MCP_AUTH_TOKEN=<random-token-at-least-32-characters> \
node dist/index.js
```

The MCP URL is `http://127.0.0.1:3000/mcp`. Publish it as HTTPS through the reverse proxy and pass the token as:

```http
Authorization: Bearer <MCP_AUTH_TOKEN>
```

Example remote client configuration for clients that support URL and custom headers:

```json
{
  "mcpServers": {
    "opnsense": {
      "url": "https://mcp.example.com/mcp",
      "headers": {
        "Authorization": "Bearer ${MCP_AUTH_TOKEN}"
      }
    }
  }
}
```

Client configuration formats vary. Store the token in the client's secret facility rather than committing it in a configuration file.

### Docker Compose

`compose.yaml` binds port 3000 to host loopback so a reverse proxy can terminate TLS safely.

```sh
export OPNSENSE_URL=https://firewall.example
export OPNSENSE_API_KEY=...
export OPNSENSE_API_SECRET=...
export MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
export MCP_ALLOWED_HOSTS=mcp.example.com
docker compose up -d --build
```

When connecting directly to `localhost:3000` during development, include `localhost` in `MCP_ALLOWED_HOSTS`. The unauthenticated health endpoint is available at `/health` and returns no target or credential details.

### Remote Security

- `MCP_AUTH_TOKEN` is mandatory for HTTP transport and must contain at least 32 characters.
- `MCP_ALLOWED_HOSTS` is mandatory when binding to a non-loopback address and prevents Host-header DNS rebinding.
- Requests with a browser `Origin` header are rejected unless the exact origin appears in `MCP_ALLOWED_ORIGINS`.
- `MCP_MAX_SESSIONS`, `MCP_SESSION_TTL_MS`, and `MCP_RATE_LIMIT_PER_MINUTE` bound remote resource use.
- Keep `OPNSENSE_TLS_VERIFY=true`. Use `OPNSENSE_CA_FILE` for an internal CA rather than disabling verification.
- Keep `OPNSENSE_WRITE_MODE=disabled` for monitoring-only deployments.
- Restrict the OPNsense API user with effective ACL privileges and `user-config-readonly` where appropriate.
- Put the MCP endpoint behind HTTPS, firewall policy, and preferably a VPN or private network.

`MCP_ALLOW_UNAUTHENTICATED=true` exists only for isolated local development and should never be used for a remotely reachable listener.

### Stdio Compatibility

Local clients can still launch the server as a subprocess:

```sh
OPNSENSE_URL=https://firewall.example \
OPNSENSE_API_KEY=... \
OPNSENSE_API_SECRET=... \
MCP_TRANSPORT=stdio \
node dist/index.js
```

### Configuration

**Single instance (env)**

- `OPNSENSE_URL`: firewall base URL.
- `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET`: dedicated API credentials.
- `OPNSENSE_INSTANCE_NAME`: optional label (default `default`).
- `OPNSENSE_WRITE_MODE`: `disabled`, `plan`, or `enabled`.
- `OPNSENSE_CA_FILE`: optional private CA PEM file.
- `OPNSENSE_TLS_VERIFY`: defaults to `true`.

**Multiple instances (JSON file)**

- `OPNSENSE_CONFIG_PATH`: absolute path to a JSON file (see [`config.example.json`](config.example.json)).
- `OPNSENSE_DEFAULT_INSTANCE`: optional override of the file's `default`.
- Per-instance fields: `name`, `url`, `api_key`, `api_secret`, optional `write_mode`, `tls_verify`, `allow_http`, `ca_file`, `timeout_ms`, `max_response_bytes`.
- Env `OPNSENSE_WRITE_MODE` / TLS / timeout defaults apply to file instances that omit those fields.
- Do not set `OPNSENSE_URL` together with `OPNSENSE_CONFIG_PATH` (the config file wins when the path is set).

**MCP transport**

- `MCP_TRANSPORT`: `http` by default, or `stdio`.
- `MCP_HOST`: listener address, default `127.0.0.1`.
- `MCP_PORT`: listener port, default `3000`.
- `MCP_PATH`: MCP endpoint path, default `/mcp`.
- `MCP_AUTH_TOKEN`: remote-agent bearer token.
- `MCP_ALLOWED_HOSTS`: comma-separated hostnames accepted in the HTTP Host header.
- `MCP_ALLOWED_ORIGINS`: comma-separated browser origins; empty rejects browser-originated requests.
- `MCP_MAX_SESSIONS`: concurrent session cap, default `100`.
- `MCP_SESSION_TTL_MS`: idle session lifetime, default one hour.
- `MCP_RATE_LIMIT_PER_MINUTE`: per-client HTTP request limit, default `120`.

Tools accept an optional `instance` argument. Omit it to use the configured default. Use `opnsense_list_instances` to discover names.

For example, a read call for system status on instance `gra`:

```json
{
  "instance": "gra",
  "module": "core",
  "controller": "system",
  "command": "status"
}
```

Stdio multi-instance example:

```sh
OPNSENSE_CONFIG_PATH=/secure/path/opnsense-instances.json \
MCP_TRANSPORT=stdio \
node dist/index.js
```

## Current Limits

- OPNsense does not publish a complete OpenAPI contract. The generated reference identifies routes and likely methods, but usually omits body schemas.
- Plugin endpoints exist only when their packages are installed and ACL-authorized.
- Semantic response validation is not yet endpoint-specific.
- The lexical risk classifier is intentionally conservative. Curated tools should eventually use an audited endpoint manifest with explicit request and response schemas.
- Plan tokens reduce accidental and mismatched execution, but MCP hosts should still present destructive tool approval to a human.
- Remote authentication currently uses a deployment-wide static bearer token rather than an OAuth authorization server. Use separate deployments or an authenticating reverse proxy when agents require distinct identities.
- Session state is in memory and is not shared across replicas. Run one replica unless external session storage and routing affinity are added.
