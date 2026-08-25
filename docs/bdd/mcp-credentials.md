# MCP Provider Credentials — Behavioral Specification

BDD acceptance contract for credential fallback in the MCP server's Omada and
OPNsense tools (issue #44). The MCP server resolves provider credentials with
the **same order the CLI uses** — explicit `tools/call` arguments →
environment variables → encrypted credential store — so an agent session with
verified store credentials never has to paste secrets into tool calls.
Scenarios marked **Implemented** are mirrored 1:1 by tests in `internal/mcp`
and `internal/cli`; each test name is listed under its scenario.

## 0. Scope

- Only credential **resolution** changes, inside `tools/call` handling. Tool
  names, argument names, and result shapes are unchanged.
- The `tools/list` input schemas for the Omada and OPNsense tools relax their
  `Required` lists to the truly mandatory arguments (`host`, plus `spec` for
  `omada_plan`). Credential arguments remain in `Properties` as optional
  overrides.
- `omada_get_info` is unauthenticated and keeps stripping credentials from
  its output (existing test coverage is retained).
- Nothing in this change writes credentials into tool output, logs, or
  evidence.

### Resolution order (all providers)

| Field | 1. explicit arg | 2. env var | 3. store entry `<provider>/default` |
| --- | --- | --- | --- |
| Omada host | `host` | `OMADA_HOST` | `host` |
| Omada client ID | `client_id` | `OMADA_CLIENT_ID` | `client_id` |
| Omada client secret | `client_secret` | `OMADA_CLIENT_SECRET` | `client_secret` |
| Omada site | `site` | `OMADA_SITE` | `site` |
| OPNsense host | `host` | `OPNSENSE_HOST` | `host` |
| OPNsense API key | `api_key` | `OPNSENSE_API_KEY` | `api_key` |
| OPNsense API secret | `api_secret` | `OPNSENSE_API_SECRET` | `api_secret` |

An explicitly supplied value at any level always wins over every lower level.
Store read failures are silently ignored (the same posture as
`credentials.Overlay`), falling through to the missing-credentials error.

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
  OMADA_CLIENT_ID / OMADA_CLIENT_SECRET environment variables or run
  `nyx credentials set omada``
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
  `TestMCPToolCallsOpnsenseCredentialsFromStore`

### S2.2 Missing OPNsense credentials keep the actionable error — **Implemented**

- **Given** no env vars, an empty store, and no credential arguments
- **When** the agent calls an OPNsense tool with only `host`
- **Then** the tool errors with
  `api_key and api_secret parameters are required: set the
  OPNSENSE_API_KEY / OPNSENSE_API_SECRET environment variables or run
  `nyx credentials set opnsense``
- **And** the test: `TestMCPToolCallsOpnsenseCredentialsMissingEverywhere`

## 3. Schema and store-path contract

### S3.1 Input schemas mark credentials optional — **Implemented**

- **When** the client reads `tools/list`
- **Then** every Omada tool requires only `host` (plus `spec` for
  `omada_plan`) and every OPNsense tool requires only `host` in `Required`
- **And** the test: `TestHandleToolsList_SchemaCredentialsOptional`

### S3.2 Store path honors `NYX_CREDENTIALS_FILE` — **Implemented**

- **Given** `NYX_CREDENTIALS_FILE` points at an empty file
- **When** credential resolution reaches the store step
- **Then** the empty custom store is consulted (and the failure is silently
  ignored), and the `NYX_CREDENTIALS_FILE` override keeps working for
  `nyx credentials` commands
- **And** the tests: `TestStoreFileDefault`,
  `TestStoreFileHonorsEnvOverride` (internal/cli, updated from
  `TestStorePathDefault`)
