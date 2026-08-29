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
| 1 (PR 1) | Reads: firmware, interfaces, firewall rules, DHCP leases (preserved contracts) | **Implemented** |
| 1 (PR 1) | Reads: NAT rules (port forward / one-to-one / source NAT), outbound NAT mode, aliases | **Implemented** |
| 1 (PR 1) | Reads (Omada): NAT port-forward / one-to-one, ALG, firewall settings, gateway presence | **Implemented** |
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
And the error contains `unexpected status 403`

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

### S2.1 Firmware info
Given `GET /api/core/firmware/running` → `{"product_version":"24.1.7","product_name":"OPNsense","product_arch":"amd64"}`
When `GetFirmwareInfo` is called
Then the result carries version `24.1.7`, name `OPNsense`, arch `amd64`

### S2.2 Interfaces
Given `GET /api/interfaces/overview/interfaces_info` → `{"interfaces":{"lan":{"description":"LAN","ipv4":"10.0.0.1/24",...}}}`
When `GetInterfaces` is called
Then each interface is returned sorted by name with IP split from the `ip/prefix` form and prefix bits as `Subnet`

### S2.3 Firewall rules
Given `GET /api/firewall/filter/search_rule` → `{"total":N,"rows":[{...}]}`
When `GetFirewallRules` is called
Then every row is returned with `Disabled` derived as `Enabled != "1"`

### S2.4 Single firewall rule by UUID
Given `GET /api/firewall/filter/get_rule/<uuid>` → a single rule object
When `GetFirewallRule` is called with the UUID
Then the rule is returned with `Disabled` derived the same way

### S2.5 DHCP leases
Given `GET /api/dhcpd/leases` → either `{"leases":[...]}` or paged `{"rows":[...]}`
When `GetDHCPLeases` is called
Then the leases are returned from whichever shape the controller used

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

## §3 Mutations (Planned — PR 2)

Reserved endpoints, listed so the PR 2 implementation is a mirror of this
table. **No mutation may ship until the matching scenario below is marked
Implemented with its test mirror** (hard lock: no opt-in escape hatch).

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
`allow_double_nat` (double-NAT protection — see topology phase).

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
  plans against an `unknown` device are refused.

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
