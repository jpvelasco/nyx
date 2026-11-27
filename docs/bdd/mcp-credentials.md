# MCP Provider Credentials — Behavioral Specification

BDD acceptance contract for credential fallback in the MCP server's Omada and
OPNsense tools (issue #44, OPNsense WM layer #121). The MCP server resolves
provider credentials with the **same order the CLI uses** — explicit
`tools/call` arguments → environment variables → Windows Credential Manager
(entry `nyx-omada-<host>` or `nyx-opnsense-<host>`, Windows only, no-op
elsewhere) → encrypted credential store — so an agent session with verified
store credentials never has to paste secrets into tool calls. Scenarios
marked **Implemented** are mirrored 1:1 by tests in `internal/mcp` and
`internal/cli`; each test name is listed under its scenario.

## 0. Scope

- Only credential **resolution** changes, inside `tools/call` handling. Tool
  names, argument names, and result shapes are unchanged.
- The `tools/list` input schemas for the Omada and OPNsense tools relax their
  `Required` lists to the truly mandatory arguments — only each tool's
  operation-specific inputs (`spec` for `omada_plan`; `device_mac` for
  `omada_get_uplink_info`; `switch_mac`/`port`/`native` for
  `omada_plan_port`/`omada_apply_port_profile`; `operation` for the NAT
  mutation pair) — never the connection or credential arguments. `host` and
  the credential arguments resolve at runtime (args → env → Credential
  Manager → store) and stay in `Properties` as optional overrides; the
  options builders report the actionable error when every supported source
  is empty.
- `omada_get_info` is unauthenticated and keeps stripping credentials from
  its output (existing test coverage is retained).
- Nothing in this change writes credentials into tool output, logs, or
  evidence.

### Selecting a connection

Vendor commands accept `--profile` and MCP vendor tools accept `profile`.
Use `omada_profile` and `opnsense_profile` on multi-provider MCP tools, or
`--omada-profile` and `--opnsense-profile` on `topology` and `port-forward`.
For `nyx audit`, repeat `--provider-profile` to select each adapter independently.

```sh
nyx audit --spec homelab.yaml --provider-profile omada=trusted --provider-profile opnsense=management
```

The equivalent single flag is `--provider-profile "omada=trusted,opnsense=management"`.
When invoking the npm launcher from PowerShell, keep the quotes around the list.
PowerShell treats an unquoted comma as an array separator, and the launcher forwards the array to Nyx as one space-joined value.

Store a named record with
`nyx credentials set omada trusted` and enter the credentials at the prompt.
The record can also carry `site` for an adapter's own selected site and
`logical_site` for an operator-defined grouping across adapters.

A named profile uses explicit inputs and only the selected encrypted entry.
If a caller overrides its host or site, they must supply credentials for that
target. An incomplete named entry reports the missing field names. The
unqualified default continues to use the resolution order below and accepts
store entries created by older releases. Authentication-free Omada info reads
only host/site metadata and can read the host of an explicitly selected profile.

### Resolution order (default connection)

| Field | 1. explicit arg | 2. env var | 3. Credential Manager (Windows only) | 4. store entry `<provider>/default` |
| --- | --- | --- | --- | --- |
| Omada host | `host` | `OMADA_HOST` | — (host never comes from WM) | `host` |
| Omada client ID | `client_id` | `OMADA_CLIENT_ID` | `nyx-omada-<host>` user name | `client_id` |
| Omada client secret | `client_secret` | `OMADA_CLIENT_SECRET` | `nyx-omada-<host>` password/blob | `client_secret` |
| Omada site | `site` | `OMADA_SITE` | — | `site` |
| OPNsense host | `host` | `OPNSENSE_HOST` | — (host never comes from WM) | `host` |
| OPNsense API key | `api_key` | `OPNSENSE_API_KEY` | `nyx-opnsense-<host>` user name | `api_key` |
| OPNsense API secret | `api_secret` | `OPNSENSE_API_SECRET` | `nyx-opnsense-<host>` password/blob | `api_secret` |

An explicitly supplied value at any level always wins over every lower level.
Store read failures are silently ignored (the same posture as
`credentials.Resolve`), falling through to the missing-credentials error.
Credential Manager reads follow the same posture: missing entries (and
non-Windows platforms, which report
"windows credential manager is not supported on this platform") fall through
to the store layer. The entry is named after the **resolved** host, so a WM
entry can supply credentials but never the host itself. Entry creation is an
operator action via `cmdkey /generic:nyx-omada-<host> /user:<client-id>
/pass:<client-secret>` or `cmdkey /generic:nyx-opnsense-<host>
/user:<api-key> /pass:<api-secret>`; the secret is never logged, written
to evidence, or returned in tool output.

## 1. Omada credential resolution

### S1.1 Env-var credentials satisfy a host-only call — **Implemented**

- **Given** `OMADA_CLIENT_ID` and `OMADA_CLIENT_SECRET` are set in the MCP
  process environment
- **And** the credential store is empty and `OMADA_HOST` is unset
- **When** the agent calls `omada_inventory` with only `{"host": ...}`
- **Then** the tool succeeds and the service receives the env-var credentials
- **And** the test: `TestMCPToolCallsOmadaCredentialsFromEnv`

### S1.2 Store credentials satisfy a credential-less call — **Implemented**

- **Given** the store (at `NYX_CREDENTIALS_FILE`) holds an `omada/default`
  entry with `host`, `client_id`, and `client_secret`
- **And** all `OMADA_*` environment variables are unset
- **When** the agent calls `omada_inventory` with no arguments at all
- **Then** the tool succeeds and the service receives the store credentials
  (host included)
- **And** the test: `TestMCPToolCallsOmadaCredentialsFromStore`

### S1.3 Explicit arguments override env and store — **Implemented**

- **Given** the store holds `omada/default` and `OMADA_*` env vars are set
- **When** the agent calls a credential tool with explicit `host`,
  `client_id`, and `client_secret` arguments
- **Then** the service receives exactly the explicit values (args beat env
  and store)
- **And** the test: `TestMCPToolCallsOmadaExplicitArgsWinOverEnvAndStore`

### S1.4 Missing everywhere keeps the actionable error — **Implemented**

- **Given** no env vars, an empty store, and no credential arguments
- **When** the agent calls a credential tool with only `host`
- **Then** the tool errors with
  `client_id and client_secret parameters are required: set the
  OMADA_CLIENT_ID / OMADA_CLIENT_SECRET environment variables or use a
  Windows Credential Manager entry nyx-omada-<host> (cmdkey
  /generic:nyx-omada-<host> /user:<client-id> /pass:<client-secret>) or
  run `nyx credentials set omada`` (the WM clause names the entry for the
  resolved host; the pinned substrings above are still contained)
- **And** the tests: `TestMCPToolCallsOmadaCredentialsMissingEverywhere`
  plus the updated `TestDispatchOmada*` / `TestDispatchOpnsense*` missing-
  credential cases

### S1.5 `omada_get_info` remains credential-free — **Implemented**

- **Given** no credentials anywhere
- **When** the agent calls `omada_get_info` with a host
- **Then** it reaches the service without credentials and its output never
  carries them
- **And** the tests: `TestDispatchOmadaGetInfo_MissingHost`,
  `TestDispatchOmadaGetInfo_Success` (existing, retained)

## 2. OPNsense credential resolution

### S2.1 Env-var or store credentials satisfy OPNsense calls — **Implemented**

- **Given** `OPNSENSE_HOST`/`OPNSENSE_API_KEY`/`OPNSENSE_API_SECRET` are set
  (env case) or an `opnsense/default` store entry with `host`/`api_key`/
  `api_secret` exists (store case)
- **When** the agent calls any OPNsense tool with no credential arguments
- **Then** the tool succeeds and the service receives those credentials
- **And** the tests: `TestMCPToolCallsOpnsenseCredentialsFromEnv`,
  `TestMCPToolCallsOpnsenseCredentialsFromStore`,
  `TestMCPToolCallsOpnsenseCredentialsFromWM`

### S2.2 Missing OPNsense credentials keep the actionable error — **Implemented**

- **Given** no env vars, an empty store, and no credential arguments
- **When** the agent calls an OPNsense tool with only `host`
- **Then** the tool errors with
  `api_key and api_secret parameters are required: set the
  OPNSENSE_API_KEY / OPNSENSE_API_SECRET environment variables or use a
  Windows Credential Manager entry nyx-opnsense-<host> (cmdkey
  /generic:nyx-opnsense-<host> /user:<api-key> /pass:<api-secret>) or
  run `nyx credentials set opnsense`` (the WM clause names the entry for
  the resolved host)
- **And** the tests: `TestMCPToolCallsOpnsenseCredentialsMissingEverywhere`,
  `TestMCPToolCallsOpnsenseCredentialsFromWM`

## 3. Schema and store-path contract

### S3.1 Input schemas mark connection and credential arguments optional — **Implemented**

- **When** the client reads `tools/list`
- **Then** every Omada tool requires only its operation-specific arguments
  (`spec` for `omada_plan`, `device_mac` for `omada_get_uplink_info`,
  `switch_mac`/`port`/`native` for
  `omada_plan_port`/`omada_apply_port_profile`) and every OPNsense tool
  only its operation inputs (`uuid`, `operation`, …) — and no tool requires
  `host` or any credential argument in `Required`, because every
  connection argument resolves at runtime (args → env → Credential
  Manager → store) and the options builders report the actionable error
  when every supported source is empty
- **And** the tests: `TestHandleToolsList_SchemaCredentialsOptional`

### S3.2 Store path honors `NYX_CREDENTIALS_FILE` — **Implemented**

- **Given** `NYX_CREDENTIALS_FILE` points at an empty file
- **When** credential resolution reaches the store step
- **Then** the empty custom store is consulted (and the failure is silently
  ignored), and the `NYX_CREDENTIALS_FILE` override keeps working for
  `nyx credentials` commands
- **And** the tests: `TestStoreFileDefault`,
  `TestStoreFileHonorsEnvOverride` (internal/cli, updated from
  `TestStorePathDefault`)

## 4. credentials_status (read-only)

### S4.1 Store completeness and env-var presence — **Implemented**

- **Given** the store holds an `omada/default` entry with every required
  field and an `opnsense/default` entry missing `api_secret`
- **And** `OMADA_CLIENT_ID` is set and the other credential env vars are
  unset
- **When** the agent calls `credentials_status` with no arguments
- **Then** the tool returns JSON with `store` entries that name the
  provider and entry, whether required fields are present, and any
  missing field names — never field values
- **And** `env` is a map of `OMADA_*` / `OPNSENSE_*` names to booleans
  (set / unset), never values
- **And** the tool does not reach a controller
- **And** the tests: `TestCredentialsStatusEmptyStore`,
  `TestCredentialsStatusReportsCompletenessAndEnvPresence`,
  `TestCredentialsStatusStoreOpenError`
