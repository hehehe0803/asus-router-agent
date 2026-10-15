"""Finite field selection prevents unrestricted upstream response disclosure."""
import json
from .errors import RouterError

FIELDS = frozenset('aimesh nodes level type parent_connection ports node_alias port link_enabled cap link_rate max_rate led wlan guest ddns radio_index guest_index updated status_code scope slots vpnc_id state_code error_code egress_verified gaps plan phase hash operation risk expires_at created_at backup_required verification before_present after_present total_known path total_changes truncated authenticated device_fingerprint unit link_code cores core total_ticks used_ticks total_kib used_kib free_kib connection signal_dbm configured backend router_auth snapshots offset next_offset schema_version snapshot_id collected_at observed_at last_success freshness source data warnings capability_gaps pagination cursor next_cursor total count limit supported unsupported reason state status healthy connected model firmware device identity wan cpu ram clients vpn config hostname transport encrypted alias connection_type signal rssi band online rx_bytes tx_bytes uptime uptime_seconds used free available percent usage total_bytes used_bytes free_bytes address_type internet mode catalog schema catalog_hash group groups fields operations name category read write risk verification rollback support evidence offline native browser unknown not_collected enabled protocol default_route egress verified ip_family errors code message sources api_auth requires remaining observed current before after changes changed kind created_at'.split())
FIELDS |= frozenset({"approval_request", "plan_hash", "after_json", "issued_at", "failure_code", "failure_stage", "verification_failure_code", "verification_failure_stage", "fetched_at", "sbstate_code", "auxstate_code", "primary", "dualwan_mode"})
FIELDS |= frozenset({"network", "interfaces", "interface", "channel_code", "bandwidth_code", "expire_seconds", "expire_remaining_seconds", "lan_access_enabled", "ap_isolation_code"})
FIELDS |= frozenset({"sysinfo", "connections", "active", "load_avg", "one_minute", "five_minutes", "fifteen_minutes", "client_associated", "client_authorized", "client_authenticated"})
FIELDS |= frozenset({"parental", "forwarding", "block_all", "rules", "rule_count", "rule_type", "schedule_present", "schedule_fingerprint", "target_alias", "external_port_count", "internal_port_count", "configured_source_filter_present", "temperature", "sensors", "sensor", "celsius"})
FIELDS |= frozenset({"update_code", "upgrade_code", "flag_code", "level_code", "reported_stable_version", "reported_beta_version", "reported_required_version", "speedtest", "native_completed_result", "download_bps", "upload_bps", "result_timestamp_utc", "result_timestamp_native", "ookla_supported"})
FIELDS |= frozenset({"aura", "all_led_enabled", "night_mode_enabled", "scheme_code", "previous_scheme_code", "openvpn_server", "wireguard_server", "wireguard_clients", "client_slot"})
FIELDS |= frozenset({"node_info", "cd_good_to_go_code", "firmware_note", "release_note", "content_fingerprint"})
FIELDS |= frozenset({"traffic", "peer_alias", "backhaul", "rx_bps", "tx_bps", "rx_avg_bps", "tx_avg_bps", "phy_rx_bps", "phy_tx_bps"})
FIELDS |= frozenset({"review", "intent", "preservation", "action", "blocked", "client_alias", "source_plan", "side_effects", "context_binding", "policy_fingerprint", "name_fingerprint", "rules_write_recoverable", "schedule"})
FIELDS |= frozenset({'openvpn_client', 'vpnc_clientlist', 'profiles', 'profile_ref', 'association', 'status_scope', 'target',
                     'dsl', 'rates', 'down', 'up', 'value', 'native_value', 'native_unit', 'unit_text', 'unit_known',
                     'flags', 'reboot', 'native_reboot_signal', 'boot_delta_seconds', 'uptime_delta_seconds',
                     'local_elapsed_seconds', 'router_elapsed_seconds', 'openvpn', 'source_flavor', 'party', 'slot'})


def safe_data(value):
    if isinstance(value, dict):
        selected = {}
        for key, item in value.items():
            key = str(key)
            if key not in FIELDS:
                continue
            if key in {"failure_code", "verification_failure_code"}:
                from .operations import FAILURE_CODES
                allowed = FAILURE_CODES | {"write_failed", "write_interrupted", "verification_read_failed", "state_mismatch"}
                item = item if isinstance(item, str) and item in allowed else "write_failed" if key == "failure_code" else "verification_read_failed"
            elif key in {"failure_stage", "verification_failure_stage"}:
                item = "write" if key == "failure_stage" else "verify"
            selected[key] = safe_data(item)
        return selected
    if isinstance(value, (list, tuple)):
        return [safe_data(v) for v in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise RouterError("invalid_output", "Output contains unsupported values.")


def envelope(data, source="local", observed_at=None, freshness="unknown", capability_gaps=None, fetched_at=None):
    if freshness not in {"fresh", "router_cached", "applied_unverified", "verified", "stale", "unknown", "not_collected", "unsupported", "auth_required", "unreachable"}:
        raise RouterError("invalid_output", "Invalid freshness state.")
    return {"schema_version": 1, "source": source, "fetched_at": fetched_at, "observed_at": observed_at, "freshness": freshness, "data": safe_data(data), "capability_gaps": safe_data(capability_gaps or [])}


def emit(value):
    print(json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False))
