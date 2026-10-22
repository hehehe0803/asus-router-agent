# Released native source contract

Runtime remains pinned to `asusrouter==1.21.3`. The packaged inventory identifies stable source revision `8de97bfa8ffe3efa2f6d1ec30bb95187d13ab37a`; see [the released source](https://github.com/Vaskivskyi/asusrouter/tree/8de97bfa8ffe3efa2f6d1ec30bb95187d13ab37a). The model/firmware labels in the inventory describe its planning target, not verified support on a user's device.

Existing bounded native WAN reads add `lease_native`, `expires_native`, `xlease_native` and `xexpires_native` independently for slots 0/1. Timing integers and strict decimal strings are bounded to `-2**31..2**32-1`; no sentinel, unit or clock meaning is assigned.

The new radio selection is only `closed`, normalized to `hidden` for the two existing radio slots. Security and mode fields (`auth_mode_x`, `crypto`, `mfp`, `nmode_x`, `country_code`) remain uncollected: the pinned native mappings do not establish finite permitted domains. No security-code enum or interpretation is added.

For the six existing guest slots, the additions are `bandwidth_limit_enabled`, `hidden`, `sync_nodes_enabled`, `download_limit_native`, `upload_limit_native`, `bss_maxassoc_native` and `maxassoc_native`. Boolean parsing accepts the pinned converter's finite string vocabulary, booleans and integers 0/1; unknown values produce a static malformed-response error. Guest numeric settings use bounded nonnegative signed-32-bit integers, excluding booleans. Missing, null and empty new settings yield null with explicit unavailable gaps.

Source observation age remains unknown. No address, SSID, password or raw vendor text is added to these outputs. Settings do not prove enforcement, RF state, AiMesh synchronization, effective bandwidth, route selection, throughput or egress.

Source mappings: [WAN hook constants](https://github.com/Vaskivskyi/asusrouter/blob/8de97bfa8ffe3efa2f6d1ec30bb95187d13ab37a/asusrouter/modules/endpoint/hook_const.py), [radio and guest mappings](https://github.com/Vaskivskyi/asusrouter/blob/8de97bfa8ffe3efa2f6d1ec30bb95187d13ab37a/asusrouter/modules/wlan.py), [native transport methods](https://github.com/Vaskivskyi/asusrouter/blob/8de97bfa8ffe3efa2f6d1ec30bb95187d13ab37a/asusrouter/asusrouter.py). These methods are constrained existing call sites, not an arbitrary endpoint or NVRAM interface.

Public audit resources retain their previously sanitized metadata. No household live evidence or private captures are included. Synthetic request and normalization tests establish only their explicit offline contracts. Production backup admission and unsupported recovery paths remain disabled.
