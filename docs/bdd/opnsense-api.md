# OPNsense API — BDD Acceptance Contract

This document is the BDD acceptance contract for the OPNsense REST client in
`internal/providers/opnsense` and the cross-provider topology / `nat_check`
surface built on top of it. Scenarios marked **Implemented** are mirrored
1:1 by named tests:

- Client core & reads — `internal/providers/opnsense/client_core_test.go`
  and `internal/providers/opnsense/client_reads_test.go` (httptest
  fake-controller servers); Omada NAT/config reads —
  `internal/backends/omada/nat_test.go`.
- Topology verdicts — `internal/topology/topology_test.go` (pure unit tests,
  no network).
- `nat_check` — `internal/providers/opnsense/provider_natcheck_test.go`,
  `internal/providers/omada/provider_natcheck_test.go`, and the spec
  validation cases in `internal/intent/spec_test.go` plus the engine
  dispatch cases in `internal/audit/engine_natcheck_test.go`.

Scenarios marked **Planned** are reserved for later phases and have no tests
yet.

- API reference: <https://docs.opnsense.org/development/api.html>
- Path convention: `https://<host>/api/<module>/<controller>/<command>/[params]`
- Auth: HTTP Basic — API key as username, API secret as password. The API is
  stateless; there is no session, token, or re-login.
- TLS verification is ON by default; opt out per-run with `--skip-tls-verify`
  or pin the controller CA with `--ca-cert <pem>`.

## §0 Scope

| Phase | Surface | Status |
| ----- | ------- | ------ |
| 1 (PR 1) | Client core (`do` GET + POST/JSON, mutex, retry/backoff, paged-list helper, logger) | **Implemented** |
| 1 (PR 1) | Reads: system info, interfaces, firewall rules, DHCP leases (preserved contracts) | **Implemented** |
| 1 (PR 1) | Reads: NAT rules (port forward / one-to-one / source NAT), outbound NAT mode, aliases | **Implemented** |
| 1 (PR 1) | Reads (Omada): NAT port-forward / one-to-one, ALG, firewall settings, gateway presence | **Implemented** |
| 1 (PR 1) | Inventory snapshot (interfaces as networks + device entries + rule/lease counts) + `nyx opnsense inventory` / `opnsense_inventory` MCP tool | **Implemented** |
| 1 (PR 1) | Topology report + `nat_check` assertion + `nyx topology` / MCP surface | **Implemented** |
| 2 (PR 2) | Mutations: NAT add/set/del, alias add/set/del, `filter_base/apply`, commit/flush | Planned |

## §1 Authentication & Core Behavior

### S1.1 Basic auth on every call
Given a client created with API key `k` and secret `s`
When any API call is made
Then the request carries `Authorization: Basic` with username `k` and password `s`

### S1.2 Unauthorized
Given a controller that responds HTTP 401
When any API call is made
Then the error contains `authentication failed — check API key and secret`
And no retry is attempted (stateless auth: a bad credential cannot be repaired by retry)

### S1.3 Resource not found
Given a controller that responds HTTP 404
When any API call is made
Then the error contains `resource not found` and the requested API path
And no retry is attempted (404 is a stable failure)

### S1.4 Transient server failure is retried with backoff
Given a controller that responds HTTP 503 twice and then HTTP 200
When a GET is made
Then the request is attempted 3 times before success
And the delays between attempts are 500 ms and 1 s (500 ms base, doubling, capped at 5 s)
And no retry log event is emitted for the final successful attempt

### S1.5 Retry budget exhausted
Given a controller that always responds HTTP 500
When a GET is made
Then the request is attempted exactly 4 times (1 initial + 3 retries)
And the error contains `unexpected status 500`

### S1.6 Transport errors are retried
Given a client pointing at an unreachable host
When any API call is made
Then the error contains `connecting to OPNsense`
And the retry budget applies (4 total attempts)

### S1.7 4xx (non-401) is not retried
Given a controller that responds HTTP 403
When any API call is made
Then the request is attempted exactly once
And the error contains `permission denied`, the requested API path, and the actionable hint `lacks the privilege for this endpoint; grant the matching page privilege to the user (System ‣ Access ‣ Users)`
And other 4xx codes contain `unexpected status <code>` and are never retried
And the test: `TestDoForbiddenPrivilegeHint` (403 → privilege hint, no retry) and `TestDoClientErrorNoRetry` (403 attempted exactly once)

### S1.8 Requests are serialised
Given two concurrent calls on one client
When both run
Then no two requests are in flight at the same time (internal mutex)

### S1.9 Context cancellation stops retries
Given a cancelled context
When a GET against a failing controller is made
Then the call returns promptly without retry sleeps
And the error wraps the context error

### S1.10 Optional operation logging
Given a client with a logger attached via `SetLogger`
When a request is retried
Then a `retry` event is logged with the method, API path, attempt number, and delay
And no log event carries credentials, hostnames, or IP addresses

## §2 Reads

Every read returns typed data decoded from the documented wire shape; a
malformed JSON body yields an error containing `decoding <what> response`.

### S2.1 System information
Given `GET /api/diagnostics/system/system_information` → `{"name":"fw","versions":["OPNsense 24.1.7_2-amd64","FreeBSD 14.2-RELEASE-p1","OpenSSL 3.0.13"],"updates":"ok"}`
When `GetSystemInformation` is called
Then the product version is `24.1.7_2` (product name and architecture stripped from the `OPNsense` entry) and the arch is `amd64`
And the FreeBSD and OpenSSL entries are exposed without their prefixes
And when the product entry carries no known-arch suffix, the version is the whole entry and the arch is empty (never guessed)

### S2.2 Interfaces
Given `GET /api/interfaces/overview/interfaces_info` answers in one of two shapes: the pre-26.x name-keyed map `{"interfaces":{"lan":{"description":"LAN","ipv4":"10.0.0.1/24","ipv4_gateway":"10.0.0.254"}}}` or the 26.x paged rows shape `{"total":N,"rows":[{"identifier":"lan","description":"LAN","addr4":"10.0.0.1/24","ipv4":[{"ipaddr":"10.0.0.1/24"}],"gateways":["10.0.0.254"],...}]}`
When `GetInterfaces` is called
Then the rows shape is tried first (26.x-first, like the dual-backend lease routes) and a body with no `rows` field falls back to the legacy map, so both decode to the same interface list
And each interface is returned sorted by name with the IP split from the `ip/prefix` form, prefix bits as `Subnet`, and the first gateway entry as `Gateway`
And a rows entry whose `identifier` is empty (an unassigned device such as `enc0`/`pflog0`) carries no configuration and is skipped
And the legacy `DHCP` flag is read only from the map shape (the rows shape has no equivalent), so a rows-shaped interface reports `DHCP=false`

### S2.3 Firewall rules
Given `GET /api/firewall/filter/search_rule` → `{"total":N,"rows":[{...}]}`
When `GetFirewallRules` is called
Then every row is returned with `Disabled` derived as `Enabled != "1"`

### S2.4 Single firewall rule by UUID
Given `GET /api/firewall/filter/get_rule/<uuid>` → a single rule object
When `GetFirewallRule` is called with the UUID
Then the rule is returned with `Disabled` derived the same way

### S2.5 DHCP leases (dual-backend route probing)
Given the active DHCP backend's route is probed in order: `GET /api/dnsmasq/leases/search` (26.x default), then `GET /api/dhcpd/leases` (pre-26.x), each returning either `{"leases":[...]}` or paged `{"rows":[...]}`
When `GetDHCPLeases` is called
Then the first route that answers (a success or a stable non-404) wins; a 404 falls through to the next route, and a 403/401/other 4xx is returned immediately as the stable privilege/credential error (never retried, masked, or hidden behind a fallback)
And both response shapes decode to the same lease list

### S2.6 Port forward rules (destination NAT)
Given `GET /api/firewall/d_nat/search_rule?current=1&rowCount=500` →
`{"total":1,"rows":[{"rule":[{"uuid":"u1","interface":["wan"],"protocol":"tcp","source":{"network":"any"},"destination":{"network":"203.0.113.1","port":"443"},"local-port":"443","descr":"web-iot"}]}]}`
When `GetPortForwardRules` is called
Then the first rule row's flat representation carries source `any`, destination `203.0.113.1`, port `443`, label `web-iot`, interfaces `[wan]`
And rows missing the `rule` array are skipped, not an error

### S2.7 One-to-one NAT rules
Given `GET /api/firewall/one_to_one/search_rule` → paged rows each carrying a `rule` object
When `GetOneToOneRules` is called
Then each row is decoded leniently (uuid, enabled, disabled flag, interface, protocol, source/destination nets, description)
And a missing `rule` array yields no rule, not an error

### S2.8 Source NAT rules
Given `GET /api/firewall/source_nat/search_rule` → paged rows each carrying a `rule` object
When `GetSourceNatRules` is called
Then each rule's interface, source/destination nets, local address, mode, and description are captured
And the generic outbound-NAT row (`snat_mode` field) is preserved in `SNATMode`

### S2.9 Outbound NAT mode
Given `GET /api/firewall/source_nat/get` → `{"filter":{"general":{"snat_mode":{"automatic":{"selected":0},"hybrid":{"selected":0},"advanced":{"selected":0},"disabled":{"selected":1}}}}}`
When `GetOutboundNatMode` is called
Then the mode is `disabled` — the entry whose `selected` flag is 1 (one of `automatic|hybrid|advanced|disabled`)
And the mode is the key double-NAT signal: a transparent-proxy OPNsense must not NAT

### S2.10 Aliases
Given `GET /api/firewall/alias/search_item?current=1&rowCount=500` →
`{"total":1,"rows":[{"uuid":"u1","name":"WEB","type":"host","address":"10.0.40.10","description":"web server","details":["10.0.40.10"],"enabled":"1"}]}`
When `GetAliases` is called
Then the alias is returned with its name, type, address list, and description
And a missing `uuid` yields an empty ID, not an error

### S2.11 Inventory snapshot (read-only)
Given a firewall reachable via its interfaces, system info, firewall-rules, and DHCP-lease endpoints
When the provider's `Inventory` (or the `opnsense_inventory` MCP tool / `nyx opnsense inventory`) is called
Then the interfaces fetch is mandatory and a failure there fails the whole call
And system info, firewall rules, and DHCP leases are best-effort: each failure is recorded as a `Warning` and the snapshot is still returned (rules reported as unknown, client count `0`)
And one device entry of type `gateway` is emitted per interface that carries an IPv4 address, named after the interface, with `NetworkGateways` mapping each interface name to its gateway
And the controller version/arch come from the product-version entry (never guessed); OPNsense exposes no managed-device inventory, so model/firmware/upgrade stay empty and no ACL scopes are reported
And `ClientCount` is the DHCP-lease count (0 when the lease fetch failed)
And a 200 OK that decodes to zero networks (an unparseable or empty interface list) is not a silently empty topology: the snapshot carries an explicit warning (and the import path adds the same warning to its result) pointing at the controller version / `--debug` raw payload
And each warning is displayed exactly once: the CLI layer prints them to stderr, the JSON surfaces keep them structured, and the human renderer (`RenderInventory`, OPNsense and Omada alike) does not repeat them
And the test: `TestProviderInventory` plus `TestRenderInventory` and `TestOpnsenseServiceInventory` / `TestDispatchOpnsenseInventory`

### S2.12 Import privilege degradation (least-privilege API user)
Given a live gateway where the API user lacks the page privileges for the firewall-rules route and the DHCP-lease route (both answer a stable 403, never retried)
When `ImportSpec` (or the `opnsense_import` MCP tool / `nyx opnsense import`, or `nyx opnsense check`, which imports first) is called
Then the spec is still returned: networks come from the interfaces endpoint, `Policies` is empty and `ClientCount` is 0
And an explicit `Warning` is appended for each unavailable read — `firewall rules unavailable: … — the spec has no policies; grant the Firewall: Filter page privilege (System ‣ Access ‣ Users) to the API user to import them` and the DHCP-lease analogue — so a 0-policy import never reads as a clean pass
And only the stable 403 degrades: a 401 (revoked or wrong credential), a transport failure, or a 5xx on the rules or lease fetches is fatal, because a silent 0-policy spec from a broken key or an unreachable controller would hide the real problem
And the degrade warnings ride the structured `Warnings` channel and surface in `import`, `check`, and the MCP tool output alike (the CLI prints each to stderr exactly once)
And the test: `TestImportSpecPrivilegeDegradation` (both routes 403 → zero-policy/zero-client spec with degrade warnings; rules-only 403 → lease count survives and exactly one degrade warning; 401 on rules → fatal)

### S2.13 Minimum page-privilege set
Given the OPNsense provider's read endpoints
When an API user is scoped with the smallest page-privilege set that keeps each surface usable
Then `info` and `inventory` require the **Dashboard** page only (both `system_information` and `interfaces_info` are covered by it; the firmware endpoints need the separate System: Firmware privilege and are never read)
And a full `import` additionally requires **Firewall: Filter** (rules → policies) and the **Diagnostics: DHCP** page (leases → client estimate); a user missing either still gets a usable, warned import per S2.12 instead of a fatal error
And the `nat_check` surface requires the **Firewall: NAT** page (outbound mode plus the NAT rule listings) on top of the Dashboard-only set

## §3 Mutations (S3.1–S3.6 Implemented — PR 2 slice 1; S3.7–S3.9 Planned)

**No mutation may ship until the matching scenario below is marked
Implemented with its test mirror** (hard lock: no opt-in escape hatch).
S3.1–S3.6 (NAT CRUD) are Implemented in this slice; S3.7 (alias CRUD),
S3.8 (filter CRUD), and S3.9 (`filter_base/apply`) are Planned. S3.10
stays reserved forever.

| Endpoint | Operation | Scenario |
| -------- | --------- | -------- |
| `POST /api/firewall/d_nat/add_rule` | Create port forward | S3.1 |
| `POST /api/firewall/d_nat/set_rule/<uuid>` | Update port forward | S3.2 |
| `POST /api/firewall/d_nat/del_rule/<uuid>` | Delete port forward | S3.3 |
| `POST /api/firewall/d_nat/toggle_rule/<uuid>,<disabled>` | Enable/disable port forward | S3.4 |
| `POST /api/firewall/one_to_one/add_rule` / `set_rule/<uuid>` / `del_rule/<uuid>` | 1:1 NAT CRUD | S3.5 |
| `POST /api/firewall/source_nat/add_rule` / `set_rule/<uuid>` / `del_rule/<uuid>` | Source NAT CRUD | S3.6 |
| `POST /api/firewall/alias/add_item` / `set_item/<uuid>` / `del_item/<uuid>` | Alias CRUD | S3.7 |
| `POST /api/firewall/filter/add_rule` / `set_rule/<uuid>` / `del_rule/<uuid>` / `toggle_rule/<uuid>,<enabled>` | Firewall rule CRUD | S3.8 |
| `POST /api/firewall/filter_base/apply` | Commit staged firewall/NAT changes | S3.9 |
| `POST /api/firewall/alias/reconfigure` | Apply staged alias changes | S3.10 |

Mutations are dry-run by default: a dry-run issues **zero** POSTs. NAT writes
against a bridge/indeterminate-classified device are refused without explicit
`allow_double_nat` (double-NAT protection — see topology phase); writes
against an `unknown` device are refused **always**, even with
`allow_double_nat` (you cannot consent to a risk that was not measured).
Every NAT mutation in this slice is **staged**: it saves to the controller
config but is not in the dataplane until `filter_base/apply` (S3.9) commits
it — the plan and apply results state this explicitly (guardrail lock
below).

### S3.1 Create port forward (Implemented)
Given `POST /api/firewall/d_nat/add_rule` with body `{"rule":{"sequence":"99","interface":"lan","protocol":"tcp","destination":{"network":"10.0.40.10"},"local-port":"443","target":"10.0.40.20","descr":"web"}`
When `CreatePortForwardRule` is called
Then the request is a single POST with `Content-Type: application/json` and the exact envelope `{"rule":{...}}` (object, not array)
And the rule fields use the DNat model names: `sequence`, `interface` (comma-joined multi), `ipprotocol`, `protocol` (lowercase), nested `source`/`destination` (`network`/`port`/`not`), `local-port`, `target`, `descr`, `pass`
And a success response `{"result":"saved","uuid":"<uuid>"}` yields the new UUID
And a validation failure returns `{"result":"failed","validations":{...}}` as a stable error (no retry)
And the test: `TestCreatePortForwardRule`

### S3.2 Update port forward (Implemented)
Given `POST /api/firewall/d_nat/set_rule/<uuid>` with the same `{"rule":{...}}` envelope
When `SetPortForwardRule` is called
Then the full writable payload is posted (the controller replaces the rule content); missing uuids fail with `{"result":"failed"}` (stable 4xx, no retry)
And `set` is an upsert for unknown-but-valid uuids (controller behaviour, never relied upon)
And the test: `TestSetPortForwardRule`

### S3.3 Delete port forward (Implemented)
Given `POST /api/firewall/d_nat/del_rule/<uuid>` with an empty JSON body
When `DeletePortForwardRule` is called
Then the delete is issued against the exact uuid path; a missing uuid yields `{"result":"not found"}` as a stable error
And the test: `TestDeletePortForwardRule`

### S3.4 Enable/disable port forward (Implemented)
Given `POST /api/firewall/d_nat/toggle_rule/<uuid>,<disabled>` where the path suffix is the **`disabled`** flag (`1` = disabled, `0` = enabled)
When `TogglePortForwardRule` is called
Then the POST path embeds `<uuid>,1` to disable and `<uuid>,0` to enable (inverted polarity — `d_nat` uses the `disabled` parameter, unlike `one_to_one`/`source_nat` which use `enabled`)
And the test: `TestTogglePortForwardRule`

### S3.5 One-to-one NAT CRUD (Implemented)
Given the `one_to_one` collection with model fields `enabled` (required, default 1), `sequence` (required), `interface` (required, default wan), `type` (required, `binat|nat`), `source_net` (required), `destination_net` (required, default any), `external` (required), `natreflection`, `description`
When `CreateOneToOneRule` / `SetOneToOneRule` / `DeleteOneToOneRule` are called
Then the wire envelope is `{"rule":{...}}` (object) against `/api/firewall/one_to_one/add_rule`, `set_rule/<uuid>`, `del_rule/<uuid>`
And the toggle uses the **`enabled`** polarity: `toggle_rule/<uuid>,1` enables, `toggle_rule/<uuid>,0` disables
And `add_rule` returns `{"result":"saved","uuid":"<uuid>"}` on success
And the test: `TestCreateOneToOneRule` / `TestSetOneToOneRule` / `TestDeleteOneToOneRule`

### S3.6 Source NAT CRUD (Implemented)
Given the `source_nat` collection (model `snatrules.rule`) with fields `enabled` (required, default 1), `sequence` (required), `interface` (required, default lan), `ipprotocol` (required, default inet), `protocol` (required, default any), `source_net` (required, default any), `source_port`, `destination_net` (required, default any), `destination_port`, `target`, `target_port`, `staticnatport`, `description`
When `CreateSourceNatRule` / `SetSourceNatRule` / `DeleteSourceNatRule` are called
Then the wire envelope is `{"rule":{...}}` (object) against `/api/firewall/source_nat/add_rule`, `set_rule/<uuid>`, `del_rule/<uuid>`
And manual outbound rules only take effect with `snat_mode` = `advanced` or `hybrid` (mode drift is reported, never coerced — S4.1)
And the toggle uses the **`enabled`** polarity: `toggle_rule/<uuid>,1` enables, `toggle_rule/<uuid>,0` disables
And the test: `TestCreateSourceNatRule` / `TestSetSourceNatRule` / `TestDeleteSourceNatRule`

### PR 2 guardrail locks (binding)

- **Dry-run = zero POSTs.** A dry-run previews the diff and issues no
  mutation HTTP call — including alias get-or-create lookups.
- **No `reconfigure`** (`S3.10` stays reserved; PR 2 does not ship it).
- **Alias get-or-create by name only.** An alias is matched by name before
  create; PR 2 never auto-deletes an existing alias.
- **Filter interface derived from the source zone.** A rule whose source
  zone cannot be mapped to a firewall interface is a hard error — the
  provider must not guess the interface.
- **Staged vs live is explicit.** Each mutation scenario names whether it
  stages (`filter_base/apply` required) or applies live; the plan result
  always states the provider name and the exact API endpoints it would
  call.
- **Outbound NAT mode drift → `unknown`.** An absent or unselected
  `snat_mode` entry is reported as `unknown` and never guessed; mutation
  plans against an `unknown` device are **always** refused, even with
  `allow_double_nat`. Bridge/indeterminate refusal is overridable with
  `allow_double_nat`; `unknown` is not.
- **Wire envelope (S3.1–S3.6).** All NAT writes POST `{"rule":{...}}` —
  `rule` is an **object** (the DNat/OneToOne/SourceNat controllers read
  `getPost('rule')`), not the read-path `rows[].rule` array. `add_rule`
  returns `{"result":"saved","uuid":"<uuid>"}` on success. Toggle
  polarity: `d_nat` suffix is `disabled` (`1`=disabled); `one_to_one`
  and `source_nat` suffixes are `enabled` (`1`=enabled).

## §4 Topology & `nat_check` (Implemented — PR 1)

Every verdict below is mirrored by a named case in
`internal/topology/topology_test.go`; the `nat_check` verdicts are mirrored
by the provider tests named in the intro. Fixtures are role-generic —
no private hostnames or subnets.

### S4.1 OPNsense device role
Given an OPNsense device whose outbound NAT mode is one of `automatic|hybrid|advanced`
When the topology report classifies it
Then the role is `nat_router` and the evidence names the mode

Given an OPNsense device whose outbound NAT mode is `disabled` and it has no source-NAT rules
When the topology report classifies it
Then the role is `bridge` and the evidence notes automatic source NAT is off

Given an OPNsense device whose outbound NAT mode is `disabled` but it has source-NAT rules
When the topology report classifies it
Then the role is `indeterminate` (conflicting facts)

Given an OPNsense device whose outbound NAT mode could not be read (key absent — version drift)
When the topology report classifies it
Then the role falls back to rule evidence: source-NAT rules → `nat_router`; no NAT rules at all → `unknown`; destination-NAT rules only → `nat_router` with a caveat in the evidence

### S4.2 Omada device role
Given an Omada site with a managed gateway device
When the topology report classifies it
Then the role is `nat_router`

Given an Omada site with no managed gateway but NAT rules present
When the topology report classifies it
Then the role is `indeterminate`

Given an Omada site with no managed gateway and no NAT rules
When the topology report classifies it
Then the role is `unknown`

### S4.3 Site double-NAT risk
Given one `nat_router` and one `bridge` (the reference topology: Omada gateway upstream, transparent OPNsense)
When the topology report is built
Then the risk is `none`

Given two `nat_router` devices
When the topology report is built
Then the risk is `double_nat`

Given one `nat_router` and one `indeterminate`
When the topology report is built
Then the risk is `double_nat` (conservative: the indeterminate device may be a second NAT point)

Given only indeterminate or unknown devices (at most one NAT)
When the topology report is built
Then the risk is `indeterminate` when an indeterminate device exists, else `none`

### S4.4 `nat_check` assertion (spec: `type: nat_check`, `provider:`, `nat_mode:`)
Given an OPNsense `nat_check` with `nat_mode` equal to the observed outbound mode
When the assertion runs
Then the status is pass and the observed mode is reported

Given an OPNsense `nat_check` with `nat_mode: bridge` on a device classified `bridge`
When the assertion runs
Then the status is pass and the evidence trail is reported

Given an OPNsense `nat_check` whose expected mode/role does not match the observation
When the assertion runs
Then the status is fail with a violation naming the observed and expected values

Given an OPNsense `nat_check` where the outbound mode key is absent (version drift)
When the assertion runs
Then the status is warn, the observed mode is reported as `unknown`, and the violation states the mode was not read (never guessed); if the expected value is `unknown` the status is pass instead

Given an Omada `nat_check` with `nat_mode: present`
When the assertion runs
Then the status is pass if the site has a managed gateway, fail with a violation otherwise; a mode/role expectation against Omada is a warn (Omada does not expose an outbound mode — use OPNsense)

### S4.5 Credential resolution
Given a `nat_check` assertion with no env credentials but a matching entry in the encrypted store (`nyx credentials set <provider>`)
When the assertion runs
Then the store entry fills the connection options (entry `<provider>/default`)

Given a `nat_check` assertion with neither env nor stored credentials
When the assertion runs
Then the result is an error whose summary contains `requires` (excluded from recommendations, like `acl_check`) and no provider call is attempted

### S4.6 `nyx topology` CLI / MCP `topology`
Given a command run with a resolvable host for one provider and none for the other
When the topology report is produced
Then only the configured provider is observed and the report carries its facts plus the combined risk

Given a command with a host for a provider but incomplete credentials (host present, key/secret missing after flags → env → store)
When the topology report is produced
Then it fails with a hard error naming the incomplete credentials — never a partial verdict

Given the JSON output of `nyx topology` (or the MCP `topology` tool)
When an outbound NAT mode was not readable
Then the rendered mode is `unknown` — never guessed
