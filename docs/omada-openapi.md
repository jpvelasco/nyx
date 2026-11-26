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

## Live-site NAT

The 6.3 hardware-controller catalog defines port forwarding and one-to-one NAT under `sites/{siteId}/nat`. Each collection supports POST for create. The item paths support PUT for update and DELETE for removal. The port-forward schema includes WAN bindings, source restrictions, DMZ, protocol and translated port. One-to-one NAT has separate internal/external addresses and interface IDs. [Port forwarding](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/createPortForwarding.json) · [Update](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/modifyPortForwarding.json) · [Delete](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/deletePortForwarding.json) · [One-to-one NAT](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/createOtoNat.json) · [Update](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/modifyOtoNat.json) · [Delete](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/deleteOtoNat.json)

`omada_plan_nat` and `omada_apply_nat` read the selected live site and return the requested selectors, candidate rule IDs and before evidence. A repeated request reads the rules again, including after an operator's write timed out. Inspect WAN bindings, source restrictions and the full rule before deciding whether the request already took effect. Overlapping ports and inconclusive ranges can produce multiple candidates. A published method describes the catalog contract. Effective permissions, controller edition, gateway support and data-plane behavior still require verification before enabling each operation. The owner-aware playbook retains its double-NAT and unknown-owner refusal. [Verification tracker](https://github.com/jpvelasco/nyx/issues/386)

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

## mDNS repeater inventory

The published `getMdnsGrid` operation lists a site's configured repeater
rules with `GET sites/{siteId}/setting/service/mdns`. Its paged response
includes rule status, Bonjour profile IDs, and either AP VLANs or gateway
network IDs. The operation is site-scoped and provides no per-gateway rule
assignment or runtime verification.

`nyx omada inventory` and MCP `omada_inventory` report the observed rules. A
successful empty response is reported as zero rules. A controller that rejects
the documented operation with `-1600` reports `mdns: api-unavailable (UI-only;
configuration unknown)`. Other read failures report `unknown`. The remaining
inventory is still returned. Control and formatting characters are removed
from controller-provided mDNS strings in all inventory formats.

[TP-Link hardware controller 6.3.0 operation schema](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.3.0/operations/getMdnsGrid.json)

## Attack-defense diagnostics

`nyx omada attack-defense` reports site configuration and whether gateway
runtime state is observable. Add `--mac` to read that client's administrative
block flag. A `false` flag can coexist with a runtime firewall block. Inspect
the enforcing gateway for runtime entries, reasons, and expiry.

`nyx omada unblock-client --mac <client-mac> --confirm` removes the controller's
administrative block for one client. For runtime attack-defense blocks, use the
gateway's own administrative tools.

## Log export

`nyx omada logs export` downloads the controller's log archive for one site
through `POST /openapi/v1/{controllerId}/logs/export` with the body
`{"siteIds": ["<siteId>"], "format": 0}` — `0` for the CSV export, `1` for the
xlsx export. The controller answers `200` with
`Content-Type: application/zip` and a `Content-Disposition` attachment whose
name it supplies (for example `LogList_<timestamp>.zip`). The CSV archive
contains a single spreadsheet with the columns `LOG TYPE`, `TIME`, and
`CONTENT`.

The endpoint requires the `GLOBAL_DATA_EXPORT` privilege. A JSON body in
response to the export request is the error envelope, so the client treats any
JSON answer as failure — a zip attachment can never parse as JSON. `--out`
writes the archive to an explicit path, replacing any existing file. Without
`--out`, the attachment name is used only when it matches the controller's
export shape `LogList_<digits>.zip`; anything else — including a missing
header — falls back to `omada-log-export.zip` in the working directory. The
default path is created fresh and never overwrites an existing file.

## AP channel inventory

`nyx omada ap-channel-info` lists managed access points and reads their current
radio channels and candidate channels. `--json` produces one row per AP and
retains the controller's candidate list. Both reads use the Open API under
`sites/{siteId}/aps/{apMac}` (`radios` and `available-channel`). On OC200
firmware 6.3.0.45, the site-wide `aps/channel-info` path was registered in the
controller package and returned error `-1600` on the appliance.
[Read-only endpoint observations](https://github.com/jpvelasco/nyx/issues/315)

## Switch ACL readback

Switch ACL listings preserve `biDirectional` when the controller returns it and
use `name` when `description` is empty. A missing flag means the value was
unavailable. The published Open API does not expose switch-side ACL installation
state or a device resync timestamp that can be compared with the ACL edit. ACL
listings therefore flag device application as unverified and advise checking
actual enforcement after resync.

An Omada `acl_check` with `expect: enforced` can set `expect_bidirectional: true`
(or `false`). A differing controller value fails the assertion. A missing value
or a matching value whose device application cannot be verified produces a warning.

### Device firmware lifecycle

Device inventory reports `up_to_date` when current and latest versions agree,
`update_available` when the controller reports a newer firmware or sets its
upgrade flag, and `eol_or_current-unknown` when the controller only knows the
current firmware. The inventory uses `latest-firmware-info` as a read-only
fallback within a five-second total lookup budget. Partial and unavailable
responses leave device inventory usable.

`eol` means regular maintenance has ended under the published regional policy.
The current built-in entry covers EAP620 HD US revisions 1.0 and 1.6 only. The
vendor's US EOS list records 2022-09-30, and its non-campus policy gives a
regular maintenance end date of 2025-09-30. The advisory suggests a supported
replacement class and the EAP650 as one option. Regional variants without an
explicit match remain eligible for the ordinary firmware states.

- [TP-Link US EOL policy](https://www.tp-link.com/us/landing/business-product-eol/)
- [TP-Link US EOS list](https://www.omadanetworks.com/us/document/132177/)
- [Published firmware operation](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.4.0/operations/getFirmwareInfo.json)

## Site configuration drift

Run `nyx omada site-config snapshot` to save a baseline of the selected site's
LAN networks, switch ACLs, WLAN groups, and SSIDs. Run
`nyx omada site-config drift` to report added, removed, or modified objects,
using the normal provider flags on either command. The comparison leaves the
baseline in place. Run `snapshot` again after an intentional change to reset it.

Every baseline contains a SHA-256 hash and the full resource JSON returned by
the Open API list endpoints. Nyx writes the baseline locally under
`~/.nyx/snapshots/omada-site-config/` with owner-only file permissions. Keep
these private files out of source control and shared reports. The text and
`--json` drift reports show the resource kind, change, and a reference that
matches its key in the local baseline. The report never includes configuration
values. Site config drift measures the state returned by these endpoints, with
no dependency on controller audit log retention.

### Controller firmware checks

`nyx omada controller-firmware` checks hardware-controller firmware through the
controller's authenticated Global Other Setting View Only API. A failure or
incomplete response produces `check_unreachable`, including when the controller
cannot contact TP-Link. An exact hardware and market match may produce
`newer_available` from the embedded published version. A reference match leaves
freshness unknown. The command never installs firmware. Hardware end of
maintenance is a separate lifecycle concern.

- [Controller firmware check](https://omada-northbound-docs.tplinkcloud.com/api/documents/by-doc/doc_oc_network_6.4.0/operations/checkForHwcUpdateV2.json)
- [OC200 3.4.25 release note](https://static.tp-link.com/upload/firmware/2026/202610/20261016/Release%20Note%20OC200%28UN%29_v3_3.4.25%20Build%2020261013.pdf)

## WLAN optimization history

Use `nyx omada wlan-optimization` to list site history and
`nyx omada wlan-optimization <history-id>` to inspect the AP details for a run.
Both use the site-scoped Open API `planningHistory` GET routes. The list reports
failed AP counts by band. The detail reports the recorded AP and radio error
codes, with APs numbered in response order.

A run with `msgType=-34806` and `apNum=0` can occur when APs are present and every
band's candidate list is empty. The controller log records the per-device
exclusions. Search the local controller log with the following command.

```sh
rg 'RFPlanning' server.log | rg -i 'do not support channel deploy|error ecsp first version|does not have available channels|the ssid of ap'
```

### Managed-device firmware upgrades

`nyx omada firmware upgrade --file <image.bin> --mac <device-mac> --expected-version <version>`
previews a single managed-device upgrade. To upload and start the upgrade, add
`--confirm-reboot` and set `--timeout` long enough for the device to reboot. The
workflow uses the documented site firmware upload and manual task endpoints. It
confirms completion by polling the task and then reading the target's exact
`firmwareVersion` and the controller's `/api/info` version. A timeout or uncertain
start reports an unverified outcome. Inspect the controller before retrying.

These site endpoints target managed devices. Use the controller UI to install
an image on the controller itself. The published hardware-controller update
operation does not accept a local image.
