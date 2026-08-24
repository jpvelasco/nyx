# Omada Open API — Behavioral Specification

BDD acceptance contract for the Open API cutover. The Omada backend moves off
the undocumented internal v2 API (`/api/v2`, cookie + CSRF session login) onto
TP-Link's Omada Open API (`/openapi/v1`, OAuth2 client-credentials). Scenarios
marked **Implemented** are mirrored 1:1 by tests in `internal/` (httptest fake
controller); the rest are the target contract for the follow-up PRs and are
verified against a live 6.2.x controller during their implementation.

## 0. Scope

- The internal v2 session surface is **cut**: no cookie jar, no CSRF header,
  no `login`/`logout` session endpoints.
- Discovery (`GET /api/info`) stays unauthenticated and unchanged; it
  supplies `omadacId` and the controller version gate (>= 6.0).
- Retry machinery is kept: mutex-serialized requests, exponential backoff on
  transient failures (5xx, network errors), single re-auth on expiry.

### Phased rollout

The cutover lands in three PRs, each red→green against its own scenarios:

| Section | Content | PR | Status |
| --- | --- | --- | --- |
| §1, §2 | Auth (token mint, re-mint, logout, secret hygiene) + credential plumbing | PR 1 | **Implemented** |
| §3 | Read endpoints + wire shapes | PR 2 | Spec only — endpoints and payloads below are the target contract, not yet shipped |
| §4, §5 | Write endpoints + scope-disabled removal | PR 3 | Spec only — same caveat |

Until PR 2/PR 3 land, the production code still calls the v2-style
`setting/` subpaths (under the new `openapi/v1` base) and tests mirror that
interim state.

## 1. Authentication

### S1.1 Token mint

- **Given** a reachable controller whose `omadacId` was obtained from
  `/api/info`
- **And** a valid `client_id` and `client_secret`
- **When** the client authenticates
- **Then** it POSTs `/openapi/authorize/token?grant_type=client_credentials`
  (the query parameter is mandatory)
- **And** the JSON body is exactly
  `{"omadacId": ..., "client_id": ..., "client_secret": ...}`
- **And** it stores `result.accessToken` from the response
- **And** every subsequent request sends `Authorization: AccessToken=<token>`

### S1.2 Invalid client credentials fail fast

- **Given** an invalid `client_id` or `client_secret`
- **When** the token mint is attempted
- **Then** the controller responds with `errorCode -44106`
- **And** the client returns an error naming invalid client credentials
- **And** the failure is permanent: no backoff retry, no re-mint loop

### S1.3 Expired token re-mints once and retries

- **Given** an authenticated client whose token expired (tokens carry a 2h TTL)
- **When** a request receives `errorCode -44112` or HTTP 401
- **Then** the client mints a fresh token once and retries the original request
- **And** the mint body reuses the stored `client_id`/`client_secret`
- **And** if the re-mint fails, or the retried request expires again, the
  error propagates — a session can be re-minted at most once per request
- **And** a client that never authenticated cannot re-mint (no stored
  credentials) and the expiry error propagates unchanged
- **And** concurrent requests share the single re-mint (requests are
  mutex-serialized)

### S1.4 No session surface

- **When** any request is made
- **Then** the client sets no cookie jar and sends no CSRF token
- **When** `Logout` is called
- **Then** the in-memory token and credentials are cleared and **no HTTP
  request is made** (Open API tokens simply expire; there is no logout
  endpoint)

### S1.5 Secrets never leak

- **When** any operation (mint, re-mint, retry, error) is logged
- **Then** `client_secret`, `client_id`, the token, the controller host, and
  IP addresses never appear in the log

## 2. Credential plumbing

The credential model changes from username/password to client credentials,
uniformly across every layer.

### S2.1 Resolution order

- **Given** the CLI, audit `acl_check`, or a provider command
- **When** Omada credentials are resolved
- **Then** flags `--client-id` / `--client-secret` win
- **And** `OMADA_CLIENT_ID` / `OMADA_CLIENT_SECRET` win over the store
- **And** the encrypted store entry (`nyx credentials set omada --set
  client_id=... --set client_secret=...`) fills the rest
- **And** a missing host still errors with the existing guidance message

### S2.2 Shared provider fields

- **Given** the shared `ImportOptions` struct used by every provider
- **When** the rename lands
- **Then** the credential fields are `ClientID` / `ClientSecret`
- **And** the OPNsense provider maps its API key and API secret onto the same
  two fields (its MCP tool arguments stay `api_key` / `api_secret`)

### S2.3 Store validation

- **When** `nyx credentials verify omada` runs
- **Then** the required fields for omada are `host`, `client_id`,
  `client_secret`

## 3. Reads

### S3.1 Pagination (every list operation)

- **Given** any list endpoint
- **When** the client fetches it
- **Then** it sends `page` (1-based) and `pageSize` as query parameters (both
  required by the controller; omitting either is `errorCode -1001`)
- **And** the result envelope is `{totalRows, currentPage, currentSize, data}`
- **And** the client walks pages until the page is empty or the collected rows
  reach `totalRows`
- **And** a page that repeats page 1, or 100 pages without termination, is a
  hard error

### S3.2 Sites

- **When** the client lists sites
- **Then** it GETs `sites`
- **And** each row carries `siteId` and `name`

### S3.3 LAN networks

- **When** the client lists LAN networks for a site
- **Then** it GETs `sites/{id}/lan-networks` (single endpoint — the v2
  candidate-path fallback is gone)
- **And** the DHCP switch is read from `dhcpSettingsVO.enable`
- **And** absent `isolation`, `deviceMac`, and `origName` decode to their zero
  values without error

### S3.4 Clients (thin rows)

- **When** the client lists connected clients for a site
- **Then** it GETs `sites/{id}/networks/client` (no filter query parameter)
- **And** each row is thin: `{mac, name, type}` only

### S3.5 DHCP user-list enrichment

- **Given** the thin client rows
- **When** clients are enriched
- **Then** the client GETs `sites/{id}/setting/service/dhcp/user-list`
- **And** rows carry `ipAddress`, `macAddress`, `name`, `netId`, `netName`
- **And** each client is joined to a DHCP row by normalized MAC
- **And** on a hit the client's IP and network name are set, and its VLAN id
  is resolved from `netId` against the site's LAN networks
- **And** clients with no DHCP row keep their thin fields and no IP

### S3.6 Devices

- **When** the client lists managed devices for a site
- **Then** it GETs `sites/{id}/networks/devices`
- **And** the result is a paged envelope

### S3.7 ACL lists (per scope)

- **When** the client lists ACL rules
- **Then** it GETs `sites/{id}/acls/osw-acls` (switch) or
  `sites/{id}/acls/osg-acls` (gateway) — the unified `setting/firewall/acls`
  endpoint is gone
- **And** each rule row carries `description` (1–512 chars) in place of v2
  `name`, plus `status`, `policy`, `protocols`, `sourceIds`,
  `destinationIds`, and (switch only) `bindingType`
- **And** the row has no `type` field — the scope is derived from the path
- **And** the list result has no `aclDisable` (see §5)

## 4. Writes

### S4.1 Switch-scope create

- **When** a switch-scope rule is created
- **Then** it POSTs `sites/{id}/acls/osw-acls`
- **And** the body carries `description`, `status`, `policy`, `protocols`,
  `sourceType`, `sourceIds`, `destinationType`, `destinationIds`,
  `bindingType`, `etherType: {enable: false}`, `biDirectional: false`
- **And** the create response carries no rule id, so the caller refetches the
  list to find the new rule

### S4.2 Gateway-scope create

- **When** a gateway-scope rule is created
- **Then** it POSTs `sites/{id}/acls/osg-acls`
- **And** the body additionally carries `syslog: true`, `stateMode: 0`,
  `states: {stateNew, established, related, invalid}` (all true), and
  `direction`
- **And** omitting `stateMode` or `states` is a controller error (-1001)

### S4.3 Update

- **When** an existing rule is updated
- **Then** it PUTs `sites/{id}/acls/osw-acls/{aclId}` or
  `sites/{id}/acls/osg-acls/{aclId}` with the same writable payload as create

### S4.4 Delete

- **When** a rule is deleted
- **Then** it DELETEs `sites/{id}/acls/{aclId}` (scope-agnostic path)

## 5. Scope-disabled concept removed

- **Given** the Open API exposes no scope enable/disable flag — no
  `aclDisable` on list results, and `osg-config-mode` is a Pro-only
  config-style setting, not a master switch
- **When** the backend, provider, service, and CLI surface scope state
- **Then** the `scope_disabled` / `ACLDisable` / `SupportLanToLan`
  machinery is removed end-to-end
- **When** `acl_check` finds an enabled rule for the requested policy
- **Then** the verdict is "enforced" (pass); there is no longer a
  "stored but not enforced" failure state
- **And** apply results and inventory output carry no disabled-scope field or
  "stored rules are not enforced" text
