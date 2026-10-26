# Omada Open API — Research Notes

Findings from investigating TP-Link's **official Omada Open API** (a.k.a.
"northbound API") during the migration of nyx's Omada backend off the
undocumented internal v2 API (see "Status relative to nyx" — the backend
now uses only the Open API). All endpoint paths and schema details below
come from the officially published spec on
`omada-northbound-docs.tplinkcloud.com` (per-version docs, e.g. the 6.2.x
catalogs), cross-checked read-only against a live controller.

Gateway client-discovery SYN traffic (the controller's own probes, not
nyx scans) is documented in [omada-syn-traffic.md](omada-syn-traffic.md).

## What it is

- Base URL: `https://<controller-host>/openapi/v1/{omadacId}/...`
- Auth: OAuth2. Apps are created once in the controller UI
  (Settings → Platform Integration → Open API). For headless/agent use an
  app in **Client mode** (client-credentials grant) is required;
  Authorization Code mode is browser-interactive.
- Token mint (2h TTL, refresh token also issued):

  ```
  POST /openapi/authorize/token?grant_type=client_credentials
  body: {"omadacId": "...", "client_id": "...", "client_secret": "..."}
  → {"result":{"accessToken":"AT-...","expiresIn":7200}}
  ```

- Request auth header: `Authorization: AccessToken=AT-...`
- Every response is an envelope: `{"errorCode":0,"msg":"...","result":{...}}`
  (non-zero `errorCode` carries a message even when HTTP is 200).

nyx should treat the client id + secret like any other provider credential:
flags → env vars → encrypted store (see Credential Resolution in AGENTS.md).

## ACL surface (Security catalog)

Full ACL CRUD is exposed, per scope, with **nested** paths — the bare
`/acls` or `/firewall/acls` paths do not exist and return
`-1600 Unsupported request path`:

| Operation | Path |
|-----------|------|
| Gateway ACL list | `GET /sites/{siteId}/acls/osg-acls?page=1&pageSize=N` |
| Gateway ACL create | `POST /sites/{siteId}/acls/osg-acls` |
| Gateway ACL modify | `PUT /sites/{siteId}/acls/osg-acls/{aclId}` |
| Switch ACL list/create/modify | `.../acls/osw-acls[/{aclId}]` |
| EAP ACL list/create/modify | `.../acls/eap-acls[/{aclId}]` |
| Delete (any scope) | `DELETE /sites/{siteId}/acls/{aclId}` |
| Reorder | `POST /sites/{siteId}/acls/modifyIndex` |
| Gateway ACL config mode (read) | `GET /sites/{siteId}/acls/osg-config-mode` |
| Gateway ACL config mode (write) | `PUT /sites/{siteId}/acls/osg-config-mode` |
| Batch edit (custom ACLs, **Omada Pro only**) | `POST /sites/{siteId}/acls/gateway-acls/batch-edit` |
| Batch delete | `POST /sites/{siteId}/acls/gateway-acls/batch-delete` |
| Hit counts / export | per-`aclId` sub-paths under `/acls/...` |

The list endpoints **require** `page` and `pageSize` query parameters
(`errorCode -1001` otherwise). The rule entity fields match the internal v2
shape field-for-field: `id`, `index`, `description`, `status`, `policy`
(0 drop / 1 allow), `protocols`, `sourceIds`/`destinationIds` with
`sourceType`/`destinationType` (0 network / 1 IP Group / 2 IP-Port Group /
... / 11+ negated variants), `direction` (`lanToWan`, `lanToLan`,
`wanInIds`, `vpnInIds`), `stateMode` (0 auto / 1 manual), `states`.

`/firewall` under the Open API is **not** ACLs — it is the
stateful-connection-timeout settings (GET + PATCH + `/reset`).

## Gateway-ACL scope master flag — no write path

The internal v2 list response carries a per-scope `aclDisable` flag
(gateway scope): when `true` the controller stores gateway ACL rules but the
gateway does not enforce them. This flag is **not settable from any
surface** on a standard (non-Pro) controller:

1. **Open API:** the entire Security catalog contains no field named
   `aclDisable` (or any global ACL-enable field). The closest endpoint,
   `GET/PUT /acls/osg-config-mode`, is a different concept: `mode` =
   `0: Through profiles` / `1: Custom` (where rule *sets* come from, not
   whether the scope is active), and the `PUT` is documented as **Omada Pro
   only** (error `-44119` on standard controllers/sites).
2. **Controller UI:** the ACL page's single reference to `aclDisable` is
   read-only; for the gateway scope the UI renders a static informational
   label (no toggle) when the device does not advertise gateway-ACL support.
   Per-rule enable/disable toggles exist, but they act only when the scope
   itself is active.
3. **Device CLI:** in controller-adopted mode the device's local web UI is
   disabled and its SSH CLI is troubleshooting-only (config writes are
   rejected in controller mode).

Consequence for nyx: the post-migration feature shape is **surface-and-explain** —
`omada_apply_acl` carries the per-scope `before`/`after` rule-list evidence,
inventory records a `rule_count` per scope (a listed scope is active), and the
recommendation engine explains that the gateway scope has no enable surface via
any API; rule CRUD remains stored but inert at the gateway when unsupported.

## NAT surface — reads only, no live-site write path

The Open API exposes NAT **reads** for a live site (`GET
sites/{siteId}/nat/port-forwardings`, `.../nat/one-to-one-nat`,
`.../nat/alg`, plus the insight/firewall settings nyx observes), and those
reads are what `nat_check`, `omada_nat_facts`, and the plan/apply evidence
use. There is **no live-site NAT write path** on the Open API:

1. Port-forwarding writes exist only on the controller's **internal web
   UI API** (`/{omadacId}/api/v2/...`, cookie + CSRF), which nyx does not
   call — the v2 API is fully cut from the backend by design.
2. The Open API's NAT *template* family (`sitetemplates/{tid}/nat/...`)
   manages **site templates**, a different product concept from a live
   site's gateway NAT, and community/SDK reports show the template write
   verbs are unreliable on standard controllers (-1600 path/method
   confusion, spec parameter bugs).
3. Independent implementers (Omada MCP servers, Terraform providers)
   converge on the same finding: port-forward CRUD is "internal web UI
   API only".

Consequence for nyx (#139): the Omada NAT write surface is an honest
**HOLD**. `omada_plan_nat` / `omada_apply_nat` (and the `nyx omada
plan-nat` / `apply-nat` CLI extras) exist so agents discover the refusal
with evidence instead of a missing tool: the plan reads the collection as
before-evidence and returns outcome `refused` with the write-surface
explanation; the apply returns identical before/after evidence and can
never mutate — dry-run or not. `omadaNatHoldNote`
(`internal/providers/omada/provider.go`) is the single source of truth
for the explanation; configure NAT via the controller UI or use
`provider: opnsense`, whose NAT write path is fully supported.

## Port speed (configured, not negotiated)

`GET sites/{siteId}/switches/ports/overview` and
`POST sites/{siteId}/devices/uplink-info` both carry `linkSpeed` /
`duplex`. Those fields are the port's **configured** speed setting
(`0` Auto, `1` 10M, `2` 100M, `3` 1000M, `4` 2500M, `5` 10G; duplex
`0` Auto / `1` Half / `2` Full), not the negotiated link state.

Live 6.2.14 observation: connected copper ports left on Auto report
`linkSpeed: 0` / `duplex: 0` even when the far end is 1G full-duplex;
down SFP ports report `linkSpeed: 3` while down. Per-port follow-ups
(`ports/{n}`, `ports/{n}/status`, `ports/{n}/stat`) all return
`errorCode -1600: Unsupported request path`. There is no LLDP-neighbor
endpoint on the wrapped 6.2.14 surface.

Consequence for nyx: do not treat `linkSpeed: 0` as link-down or
unknown. Service types stamp `link_speed_source: "configured"`.
Negotiated speed is unobservable from the controller; the
`client-link-topology` node is the fallback signal for the
managed→unmanaged hop.

## TLS quirk (Windows)

The controller requests a **TLS renegotiation** mid-connection on some
Open API responses. PowerShell `Invoke-WebRequest` aborts these with a
"no-resp" failure; `curl.exe` handles them fine. All Open API client
code must use an HTTP stack that tolerates renegotiation (Go's
`crypto/tls` allows client-initiated renegotiation handling; verify in
tests) — do not port the old PowerShell probe scripts verbatim.

## Status relative to nyx

- nyx's Omada backend is **fully migrated to the Open API**: auth is
  client-credentials, and every read and write goes through
  `/openapi/v1/{omadacId}/...` (base path order pinned in BDD S0.1).
  The internal v2 API is no longer called.
- The Open API exposes no per-scope ACL enable/disable flag (see above),
  so inventory records `rule_count` per scope and `omada_apply_acl`
  surfaces `before`/`after` evidence instead of a scope-disabled marker.
- Wire shapes observed live: `sites` rows carry `siteId` (no `id`);
  `lan-networks` rows carry `purpose` as `integer(int32)` (0: VLAN,
  1: interface) — pinned in BDD S3.3; `acls/osw-acls` and `acls/osg-acls`
  work without a `type` query.
