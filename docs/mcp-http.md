# Design: HTTP Transport for `nyx mcp`

**Status:** Design only (issue #15). Not implemented.
**Related:** #2 (credential vault), #14 (harness wiring), `docs/bdd/mcp-credentials.md`, `docs/naming.md`

This document settles the binding, authentication, and session model for a
future HTTP transport. It does **not** implement that transport. `nyx mcp
serve` remains stdio-only; any other `--transport` value is rejected with
`only stdio transport is supported in v1` (`internal/cli/mcp.go`).

## Why stdio is the only transport today

The MCP server is a local agent-harness child process. The harness
(`nyx mcp config --harness claude|codex`) spawns `nyx mcp serve` and
speaks newline-delimited JSON-RPC on stdin/stdout. That shape is
deliberate:

- **Process lifetime is the session.** When the harness exits, the child
  dies. There is no listener, no port, and no leftover socket.
- **The RPC channel stays clean.** Tool-call records go to the rotating
  file logger (`~/.nyx/nyx.log`) with a per-call `trace_id`. Stdout
  carries only JSON-RPC responses — never logs, never credentials.
- **Credentials never leave the process.** Provider credentials resolve
  inside `tools/call` from **tool args → env vars → Windows Credential
  Manager (Omada only) → encrypted store**. The harness config snippet
  lists env-var *names* only. The controller API is reachable only
  through the declared tool surface.

HTTP is stubbed because a shared listener changes every one of those
invariants. A bound socket outlives a single harness, can be reached by
anything on the host (or the network, if bound that way), and needs an
auth and session story the stdio child never required. Until that story
is implemented, the CLI refuses every non-stdio transport rather than
half-shipping a listener.

## Goals

If HTTP is implemented later, it exists so **one** `nyx mcp` process can
serve multiple local agent harnesses instead of a per-session stdio
spawn. The tool surface, result shapes, dry-run-default mutations, and
credential resolution order stay identical to stdio.

## Non-goals (v1)

The following are explicitly out of scope for a first HTTP transport.
They are not "later in the same PR"; they are a different product.

| Out of scope | Why |
|--------------|-----|
| Remote internet exposure | The process holds live controller credentials and a mutation surface (`omada_apply_acl`, `omada_apply_port_profile`, `opnsense_apply_nat`). It is a local operator tool, not a public API. |
| Multi-tenant / multi-user | One operator, one vault, one controller. No per-tenant isolation, no user accounts, no shared-hosting mode. |
| mTLS | Overkill for localhost. Adds cert provisioning the operator does not have today. Revisit only if a LAN-bind mode is ever designed as its own issue. |
| Putting controller secrets on the wire | HTTP must not become a secret-paste surface. See [Credential vault (#2)](#relationship-to-2-credential-vault). |
| Changing the tool surface | Same tools, same `CheckResult` JSON, same 5-minute `toolCallTimeout`. Transport is a new listener, not a new MCP. |

## Binding

**Default: localhost only.** Loopback (`127.0.0.1`, and `::1` if dual-stack)
is the only address a v1 listener may bind. The process is an operator
tool on `mgmt-host`; nothing on the LAN or the internet should be able
to open it.

**No implicit LAN or wildcard bind.** `0.0.0.0`, `::`, a `management`
address, or any non-loopback interface is refused. "It bound to all
interfaces because I omitted the flag" is a security defect, not a
convenience.

**Explicit bind flag, if ever implemented.** A `--bind <addr>` (or
equivalent) may exist so an operator can pick the loopback address and
port. It does **not** unlock remote mode. Non-loopback values error with
an actionable message (`bind to loopback only; remote exposure is out of
scope`). There is no `--allow-remote` escape hatch in v1.

**Port.** Unspecified at design time. Implementation should pick an
ephemeral or documented default and print the bound `127.0.0.1:<port>`
on stderr (not on the RPC channel). The bound address is not a secret;
the auth token is.

## Authentication

The mutation tools and the in-process controller credentials make an
unauthenticated localhost listener unacceptable. Anything that can
`connect()` to the port could apply an ACL. Binding to loopback is the
first control, not the only one.

### Token in a header, never in the URL

- The listener requires a bearer token on every request:
  `Authorization: Bearer <token>`.
- **No secrets in URLs.** Query strings (`?token=`), path segments, and
  WebSocket subprotocols that echo the token are forbidden. URLs land in
  proxy logs, browser history, and crash reports; headers do not, if the
  operator is careful.
- The token authenticates the *MCP listener*, not the SDN controller or
  the OPNsense API. It answers "is this harness allowed to talk to this
  nyx process?" Controller credentials stay in the existing resolution
  chain and are never the HTTP credential.

### Token provisioning

- Generated at process start (or read from a dedicated env var such as
  `NYX_MCP_TOKEN`). Printed once to stderr for the operator to hand to
  the local harness. Never written to the rotating log, never included
  in tool output, never placed in the `nyx mcp config` snippet.
- Comparison is constant-time. Missing, empty, or wrong tokens get
  `401` with a generic body. Do not echo the presented value back.
- Rotating the token means restarting the process. v1 has no token
  refresh or multi-token list.

### Logging

The existing no-secrets invariant extends to the HTTP layer:

- Never log the bearer token, `Authorization` header, controller
  credentials, or store contents.
- Request logs may record method, path, status, duration, and a
  `trace_id`. They must not record headers, query strings, or bodies
  that can carry secrets.
- `logSafeError` (and the OPNsense equivalent) still strip host
  identity from backend errors. The HTTP layer does not grow a second
  logger that bypasses the PII scrubber.

## Session model

Stdio is one client, one `Server`, one `initialized` flag, one process
lifetime. HTTP has to reconstruct that isolation on a shared listener.

### One session per connection

- Each accepted HTTP connection (or MCP streamable-HTTP session) gets
  its own `Server` value: its own `initialized` flag, its own JSON-RPC
  framing, its own `trace_id` namespace.
- Sessions do not share initialize state. A `tools/call` on a session
  that has not sent `initialize` fails the same way stdio does
  (`server not initialized`).
- Session IDs, if the protocol requires them, are random and
  unguessable. They are correlation handles, not capabilities — knowing
  a session ID without the bearer token is not access.

### Timeout

- **Idle timeout** closes a session that has sent no frames for a
  bounded window (implementation default on the order of minutes, not
  hours). The next request on that session ID is a new session and must
  `initialize` again.
- **Per-call timeout** stays the existing 5-minute `toolCallTimeout`.
  HTTP does not raise it. A hung backend still cannot wedge the
  listener.
- Process shutdown (`SIGINT`/`SIGTERM`, same as stdio) drains or
  cancels in-flight calls and closes the listener. No session survives
  the process.

### No controller credentials in the HTTP layer

The HTTP stack authenticates the harness. It does **not** accept, store,
or multiplex controller credentials:

- No `OMADA_CLIENT_SECRET` / `OPNSENSE_API_SECRET` headers, cookies, or
  query parameters.
- No per-session overlay that lets client A plant credentials that
  client B then inherits.
- Every `tools/call` resolves credentials the same way stdio does
  today: tool args → env vars → Windows Credential Manager (Omada) →
  encrypted store (`docs/bdd/mcp-credentials.md`). The HTTP layer does
  not add a fifth source and does not skip any existing one.

Two local harnesses talking to one process therefore share the
*operator's* vault (env + store), not each other's tool-arg overrides.
An explicit `client_secret` in a `tools/call` still wins for that call
only, exactly as it does on stdio.

### Concurrency

The Omada HTTP client already serialises requests through an internal
mutex and performs a single automatic re-login on session expiry. A
shared MCP process does not change that:

- Multiple MCP sessions may dispatch overlapping `tools/call`s. The
  backend mutex keeps controller requests ordered.
- Expect serialization, not parallelism, against one controller. That
  is acceptable for v1. Do not add a second in-process Omada login to
  "speed up" HTTP.
- OPNsense and the local check backends follow their existing
  concurrency posture. HTTP does not introduce a process-wide lock
  around `run_audit`.

The controller API remains reachable only through the declared tool
surface. The HTTP listener is not a reverse proxy to the controller,
the OPNsense API, or the credential store.

## Protocol target

When implemented, target **MCP streamable HTTP** with session IDs — the
current MCP transport spec — not the legacy standalone SSE transport.
Framing, initialize, `tools/list`, and `tools/call` stay JSON-RPC 2.0
with the same method names and result shapes as stdio.

Legacy SSE is not a v1 deliverable. A second framing mode would double
the auth and session surface for no current harness requirement.

## Relationship to #2 (credential vault)

Issue #2 is the local credential vault: provision once (`nyx
credentials set`), resolve transparently, never paste secrets into
chat, specs, logs, or tool output. HTTP transport must reinforce that
vault, not bypass it.

**HTTP must not become a secret-paste surface.**

- The bearer token is a *listener* credential. It is not an Omada
  client secret, an OPNsense API secret, or a probe SSH key, and it
  must not be overloaded as one.
- Harness config for HTTP (when written) lists the listener URL and
  the token env-var *name*, the same way `nyx mcp config` lists
  `OMADA_*` / `OPNSENSE_*` names today. Values stay out of the file.
- Tool arguments may still carry an explicit credential override —
  that override already exists on stdio and is an operator escape
  hatch, not an HTTP feature. The HTTP design does not add new places
  to put those values (headers, cookies, URL, session bootstrap).
- The `credentials_status` tool (#2) reports which providers are
  provisioned. It never returns secrets. HTTP does not grow a
  "submit credentials" endpoint that would make the listener a vault
  write API.

If vault and HTTP land in different PRs, HTTP still reads the store
through the existing overlay. It does not invent a parallel
provisioning path "just for the listener."

## Implementation notes (not this change)

Leave the stub in place until a dedicated implementation issue is
accepted:

- `internal/cli/mcp.go` keeps rejecting `--transport` values other than
  `stdio`.
- `internal/mcp` stays a stdio JSON-RPC loop. Do not grow a half-open
  `net.Listener` behind the stub.
- Feature work does not edit `CHANGELOG.md`; a release-prep PR will
  mention HTTP if and when it ships.

Acceptance for an implementation PR (future) should include: loopback
bind only, non-loopback refused, bearer header required, token never
logged or placed in a URL, one `Server` per session, idle + per-call
timeouts, credential resolution unchanged from
`docs/bdd/mcp-credentials.md`, and no new secret-bearing HTTP fields.
