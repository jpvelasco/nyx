# UniFi Network map integration

Nyx uses the read-only local integration API on a UniFi OS console. The release-channel baseline checked on November 25, 2026 was Network 11.0.104. Ubiquiti publishes the 11.0 API reference under 11.0.97. Controller contract fixtures cover the requests below. Physical console verification is pending. [Release channel](https://fw-update.ubnt.com/api/firmware?filter=eq~~version_major~~11&filter=eq~~channel~~release&limit=30&sort=-created) · [API reference](https://developer.ui.com/network/v11.0.97/gettingstarted)

Create a local integration API key with read access to the target site. For the default connection set `UNIFI_HOST`, `UNIFI_API_KEY` and optionally `UNIFI_SITE`. For a named connection, use `nyx credentials set unifi home` and enter the console HTTPS origin and API key at the prompts. Supply `--set site=<site>` for an explicit site selection and `--set logical_site=<name>` for site grouping. Use the same `logical_site` on the UniFi and OPNsense connections to group their observations. The adapter sends the key in `X-API-Key` under the console path `/proxy/network/integration/v1`. It verifies TLS by default, accepts a local CA using `--ca-cert`, and refuses redirects.

`nyx topology map --connection unifi/home --connection opnsense/home` reads the selected sites. The corresponding MCP call is `network_map` with `connections` set to `["unifi/home", "opnsense/home"]`. When multiple UniFi sites are visible to the key, select a site ID or a unique name. Default maps keep native identifiers private.

| Inventory | Observations available to the map |
| --- | --- |
| Sites | Paged site IDs and names establish a unique target. |
| Adopted devices | The controller's feature list identifies switching, wireless and gateway roles. |
| Device details | Reported physical port indexes and the managed uplink's device ID establish device/port and child/parent relationships. |

The available interface fields depend on device features and model. An inaccessible detail record or missing switch port inventory is a coverage gap. The published device detail response does not identify the far-end physical port, external LLDP neighbors or effective VLAN membership on each port. A shared logical site groups a switch with a firewall without inventing a physical connection. [Sites](https://developer.ui.com/network/v11.0.97/getsiteoverviewpage) · [Adopted devices](https://developer.ui.com/network/v11.0.97/getadopteddeviceoverviewpage) · [Device detail](https://developer.ui.com/network/v11.0.97/getadopteddevicedetails)
