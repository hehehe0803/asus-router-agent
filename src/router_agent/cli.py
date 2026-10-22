"""Finite native reads and independently authorized native operations."""
import argparse
import asyncio
import re
import sys
import time
from urllib.parse import urlsplit
from .auth import auth_status, get_credentials, init_auth, load_config
from .errors import RouterError
from . import __version__
from .compact import TABLE_HELP, pack
from .output import emit, envelope
from .snapshots import SnapshotStore, private_read, state_lock, private_dir

PROTECTED_GROUPS = ('openvpn_client', 'vpnc_clientlist')
EXPANSION_PLAN_NAMES = {'forwarding': 'state.port_forwarding', 'openvpn-server': 'state.openvpn_server',
                        'wireguard-server': 'state.wireguard_server', 'wlan': 'state.wlan',
                        'vpnc': 'state.vpnc', 'openvpn-client': 'state.openvpn_client',
                        'wireguard-client': 'state.wireguard_client'}


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                          help="Compatibility flag; JSON is already the default (except help/version)")

    def error(self, message):
        raise RouterError("invalid_arguments", "Invalid arguments; use router-agent --help.", 2)


def parser():
    p = Parser(prog="router-agent", description="Bounded router evidence; native compatibility is unverified.")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    subs = p.add_subparsers(dest="command", required=True)
    auth = subs.add_parser("auth", help="User-operated desktop Secret Service onboarding", description="Manage local credentials and bounded router authentication.")
    authsubs = auth.add_subparsers(dest="auth_command", required=True)
    init = authsubs.add_parser("init", help="Store router origin and Secret Service credentials", description="Store credentials through the desktop Secret Service.")
    init.add_argument("--host", required=True, help="Exact http(s) origin")
    init.add_argument("--username", required=True)
    init.add_argument("--allow-plain-http", action="store_true", help="Explicit HTTP choice for read commands only")
    init.add_argument("--ca-file", help="PEM CA certificate file for verified HTTPS")
    authsubs.add_parser("status", help="Inspect local credential configuration", description="Inspect local configuration without router requests.")
    authsubs.add_parser("probe", help="One bounded router authentication attempt", description="Attempt one native login and bounded logout without telemetry reads.")
    cap = subs.add_parser("capabilities", help="Offline inventory; does not establish firmware support", description="Inspect checked-in capabilities; live firmware support remains unverified.")
    selectors = cap.add_mutually_exclusive_group()
    selectors.add_argument("--group")
    selectors.add_argument("--native", nargs="?", const="all", metavar="CAPABILITY_ID", help="Offline native evidence ledger; optionally one exact capability")
    selectors.add_argument('--expansion', nargs='?', const='all', metavar='CAPABILITY_ID', help='Dated implementation and remaining gates for the sixteen expansion rows')
    selectors.add_argument('--webui', nargs='?', const='all', metavar='OPERATION_ID', help='Offline firmware operation candidates; inventory is not WebUI parity')
    cap.add_argument('--family', help='Exact WebUI family; requires --webui')
    cap.add_argument('--status', choices=['unimplemented', 'partial', 'implemented'], help='WebUI implementation status; requires --webui')
    cap.add_argument('--blocker', help='Exact WebUI blocker code; requires --webui')
    cap.add_argument("--limit", type=int, default=5)
    cap.add_argument("--offset", type=int, default=0)
    subs.add_parser("status", help="Read identity, WAN, CPU and RAM", description="Read bounded native router status; source freshness may be unknown.")
    get = subs.add_parser("get", help="Read selected named telemetry groups", description="Read distinct selected native groups with identity validation.")
    named_groups = ["identity", "wan", "cpu", "ram", "clients", "vpn", "led", "wlan", "guest", "ddns", "ports", "aimesh", "network", "sysinfo", "parental", "forwarding", "uptime", "temperature", "firmware", "speedtest", "aura", "openvpn_server", "wireguard_server", "wireguard_clients", "node_info", "firmware_note", 'dsl', 'flags', 'openvpn', *PROTECTED_GROUPS]
    get.add_argument("group", nargs="+", choices=named_groups, metavar="GROUP", help="Named groups: " + ", ".join(named_groups) + ".")
    get.add_argument("--note-offset", type=int, default=None, help="Release-note character offset; firmware_note alone")
    get.add_argument("--note-limit", type=int, default=None, help="Release-note characters (1–4096, default 2048); firmware_note alone")
    traffic = subs.add_parser("traffic", help="Selected native rates for fresh aliased nodes", description="Read selected native rates after same-session aliased node resolution.")
    traffic.add_argument("kind", choices=["ethernet", "wifi", "backhaul"])
    traffic.add_argument("--node", required=True, help="Exact local node alias from get aimesh")
    traffic.add_argument("--peer", help="Distinct node alias; backhaul only")
    traffic.add_argument("--band", choices=["2ghz", "5ghz", "5ghz2", "6ghz"], help="Wi-Fi band; wifi only")
    traffic.add_argument("--backhaul", action="store_true", help="Native Ethernet backhaul selector; ethernet only")
    clients = subs.add_parser("clients", help="Read and page aliased clients", description="Page selected native client inventory; cached source age may be unknown.")
    clients.add_argument("--limit", type=int, default=10)
    clients.add_argument("--offset", type=int, default=0)
    clients.add_argument("--online", action="store_true", help="Only records explicitly reported online")
    clients.add_argument("--alias", help="Exact local client alias (client- followed by 16 lowercase hex digits)")
    snapshot = subs.add_parser("snapshot", help="Save status or list local snapshots", description="Save a bounded native status snapshot, or list snapshots locally.")
    snapshot.add_argument("--list", action="store_true")
    diff = subs.add_parser("diff", help="Compare two local snapshots", description="Compare bounded local snapshot data with pagination.", epilog=TABLE_HELP)
    diff.add_argument("--since", required=True)
    diff.add_argument("--to", required=True)
    diff.add_argument("--offset", type=int, default=0)
    diff.add_argument("--limit", type=int, default=20)
    diff.add_argument("--format", choices=["json", "table"], default="json", help="Lossless row encoding; decoder instructions below")
    plan = subs.add_parser("plan", help="Preview a native change", description="Read current state and store a native change preview; no writes are sent.")
    plan.add_argument("operation", choices=["led", "parental", "parental-block-all", "parental-rule", *EXPANSION_PLAN_NAMES])
    plan.add_argument("--enabled", choices=["on", "off"], help="LED or global parental enable setting")
    plan.add_argument("--blocked", choices=["on", "off"], help="Separate all-client internet blocking setting")
    plan.add_argument("--alias", help="Local client alias; parental-rule only")
    plan.add_argument("--type", dest="rule_type", choices=["disable", "time", "block", "remove"], help="Native parental rule intent")
    plan.add_argument("--schedule", help="Explicit native schedule literal; structure only, semantics/timezone unverified")
    plan.add_argument('--profile', help='Opaque existing VPN profile reference from a protected selector')
    plan.add_argument('--target', choices=['radio0', 'radio1', 'guest0.1', 'guest0.2', 'guest0.3', 'guest1.1', 'guest1.2', 'guest1.3'], help='Finite WLAN radio or guest target')
    operation_help = {
        "plan-show": "Inspect a stored local plan without router requests",
        "approval-request": "Print exact scope for a separate administrator approval window",
        "apply": "Apply with an administrator window and human confirmation over HTTPS; a no-op sends zero writes, but performs reads",
        "verify": "Read current state to verify a stored plan",
        "rollback": "Preview a reverse plan; separate confirmation and apply are required",
    }
    for name in ("plan-show", "approval-request", "apply", "verify", "rollback"):
        op = subs.add_parser(name, help=operation_help[name], description=operation_help[name])
        op.add_argument("plan_id")
        if name == "apply":
            op.add_argument("--window", help="Exact administrator-issued, plan-bound approval window reference")
    return p


async def _collect(groups, probe=False, *, note_offset=0, note_limit=2048):
    from .transport import TransportConfig, collect_native, probe_auth
    config, password = get_credentials()
    transport = TransportConfig.from_auth(config)
    store = SnapshotStore()
    store.ensure_key()
    with state_lock(store.state_dir):
        if probe:
            return await probe_auth(transport, password)
        key = private_read(store.state_dir / 'alias.key')
        protected = tuple(g for g in groups if g in PROTECTED_GROUPS)
        if protected:
            from datetime import datetime, timezone
            from .native_vpn_control import read_vpn
            from .protected_vpn import parse_snapshot, select_profiles
            private = await read_vpn(transport, password, fingerprint_key=key)
            snapshot = parse_snapshot(private['raw'], key, private['identity'])
            fetched_at = datetime.now(timezone.utc).isoformat()
            gaps = ['selected_settings_and_native_status_do_not_prove_tunnel_or_egress', 'profile_credentials_are_application_private', 'source_observation_time_unavailable']
            data = {'identity': private['identity']}
            sources = {'identity': {'fetched_at': fetched_at, 'observed_at': None, 'freshness': 'unknown'}}
            for group in protected:
                data[group] = {**select_profiles(snapshot, 'openvpn' if group == 'openvpn_client' else None), 'gaps': gaps}
                sources[group] = {'fetched_at': fetched_at, 'observed_at': None, 'freshness': 'unknown'}
            public_gaps = [{'group': group, 'reason': gap} for group in protected for gap in gaps]
            result = {'schema_version': 1, 'source': 'native', 'fetched_at': fetched_at, 'observed_at': None, 'freshness': 'unknown', 'data': data, 'sources': sources, 'capability_gaps': public_gaps}
            if private.get('warnings'):
                result['warnings'] = private['warnings']
            others = tuple(g for g in groups if g not in PROTECTED_GROUPS and g != 'identity')
            if others:
                passive = await collect_native(transport, password, groups=others, fingerprint_key=key, state_dir=store.state_dir)
                if passive['data']['identity'] != private['identity']:
                    raise RouterError('identity_changed', 'The target identity changed between bounded native selections.')
                result['data'].update({k: v for k, v in passive['data'].items() if k != 'identity'})
                result['sources'].update({k: v for k, v in passive['sources'].items() if k != 'identity'})
                from .catalog import canonical
                merged = {}
                for gap in [*public_gaps, *passive.get('capability_gaps', [])]:
                    merged.setdefault(canonical(gap), gap)
                result['capability_gaps'] = list(merged.values())
                result['warnings'] = sorted(set(result.get('warnings', []) + passive.get('warnings', [])))
            from .output import safe_data
            return safe_data(result)
        return await collect_native(transport, password, groups=tuple(groups), fingerprint_key=key, note_offset=note_offset, note_limit=note_limit, **({'state_dir': store.state_dir} if 'flags' in groups else {}))




def _validate_traffic_args(args):
    alias = r"node-[0-9a-f]{16}"
    if re.fullmatch(alias, args.node) is None or args.peer is not None and re.fullmatch(alias, args.peer) is None:
        raise RouterError("invalid_arguments", "Traffic targets require exact local node aliases from get aimesh.", 2)
    valid = ((args.kind == "ethernet" and args.peer is None and args.band is None)
             or (args.kind == "wifi" and args.peer is None and args.band is not None and not args.backhaul)
             or (args.kind == "backhaul" and args.peer is not None and args.peer != args.node and args.band is None and not args.backhaul))
    if not valid:
        raise RouterError("invalid_arguments", "Traffic options must match ethernet, wifi or distinct-node backhaul selection.", 2)


async def _collect_traffic(kind, node_alias, *, peer_alias=None, band=None, backhaul=False):
    from .transport import TransportConfig, collect_traffic
    config, password = get_credentials()
    transport = TransportConfig.from_auth(config)
    store = SnapshotStore()
    store.ensure_key()
    with state_lock(store.state_dir):
        return await collect_traffic(transport, password, kind, node_alias,
                                     fingerprint_key=private_read(store.state_dir / "alias.key"),
                                     peer_alias=peer_alias, band=band, backhaul=backhaul)

def _plan_store():
    from .operations import FilePlanStore
    store = SnapshotStore()
    private_dir(store.state_dir)
    return store.state_dir, FilePlanStore(store.state_dir / "plans")


def _engine(operation="led.set"):
    from .catalog import load_catalog
    from .native_backend import NativeLEDBackend
    from .operations import OperationEngine
    from .transport import TransportConfig
    config, password = get_credentials()
    directory, plans = _plan_store()
    SnapshotStore(directory).ensure_key()
    if operation.startswith("parental."):
        from .native_parental_backend import NativeParentalBackend
        backend = NativeParentalBackend(TransportConfig.from_auth(config), password, fingerprint_key=private_read(directory / "alias.key"), state_dir=directory)
    elif operation in EXPANSION_PLAN_NAMES.values():
        from .expansion_backend import ExpansionBackend
        backend = ExpansionBackend(TransportConfig.from_auth(config), password, operation=operation, fingerprint_key=private_read(directory / 'alias.key'))
    else:
        backend = NativeLEDBackend(TransportConfig.from_auth(config), password, fingerprint_key=private_read(directory / "alias.key"))
    return directory, OperationEngine(load_catalog(), backend, plans)


OPERATION_ERRORS = frozenset({"invalid_plan_id", "plan_id_mismatch", "invalid_structure", "plan_tampered", "unsupported_operation", "unsupported_fields", "expired_plan", "incompatible_plan", "approval_scope_mismatch", "before_drift", "backup_required", "replay_blocked_verify_first", "not_applied", "rollback_drift", "invalid_plan_scope", "invalid_plan_policy", "live_execution_human_handoff"})



def _plan_intent(args):
    if args.operation in EXPANSION_PLAN_NAMES:
        from .expansion_backend import validate_intent
        if args.enabled is None or any(v is not None for v in (args.alias, args.rule_type, args.schedule, args.blocked)):
            raise RouterError('invalid_arguments', 'Finite native toggle previews require --enabled and only their target selector.', 2)
        operation = EXPANSION_PLAN_NAMES[args.operation]
        intent = {'enabled': args.enabled == 'on'}
        if args.profile is not None:
            intent['profile_ref'] = args.profile
        if args.target is not None:
            intent['target'] = args.target
        validate_intent(operation, intent)
        return operation, intent
    if args.profile is not None or args.target is not None:
        raise RouterError('invalid_arguments', 'This preview does not accept a VPN profile or WLAN target.', 2)
    extras = (args.alias, args.rule_type, args.schedule, args.blocked)
    if args.operation == "led":
        if args.enabled is None or any(value is not None for value in extras):
            raise RouterError("invalid_arguments", "LED preview requires only --enabled on|off.", 2)
        return "led.set", {"enabled":args.enabled == "on"}
    from .native_parental_backend import validate_parental_intent
    if args.operation == "parental":
        if args.enabled is None or any(value is not None for value in extras):
            raise RouterError("invalid_arguments", "Parental enable preview requires only --enabled on|off.", 2)
        operation,intent = "parental.enable", {"enabled":args.enabled == "on"}
    elif args.operation == "parental-block-all":
        if args.blocked is None or any(value is not None for value in (args.enabled,args.alias,args.rule_type,args.schedule)):
            raise RouterError("invalid_arguments", "All-client blocking preview requires only --blocked on|off.", 2)
        operation,intent = "parental.block_all", {"blocked":args.blocked == "on"}
    else:
        if args.alias is None or args.rule_type is None or args.enabled is not None or args.blocked is not None:
            raise RouterError("invalid_arguments", "Parental rule preview requires a local alias and native rule type.", 2)
        operation,intent = "parental.rule", {"client_alias":args.alias,"rule_type":args.rule_type}
        if args.schedule is not None:intent["schedule"] = args.schedule
    validate_parental_intent(operation,intent)
    return operation,intent

def _execute_operation(args):
    from .approval import confirm_plan
    from .operations import PARENTAL_OPERATIONS, EXPANSION_OPERATIONS, BOUND_OPERATIONS
    if args.command == "plan":
        operation,intent = _plan_intent(args)
    else:
        directory, store = _plan_store()
        with state_lock(directory), store.lock():
            plan, state = store.get(args.plan_id)
        operation = plan.data.get("operation")
        if operation not in {"led.set",*BOUND_OPERATIONS}:
            raise RouterError("unsupported_operation", "Only finite named native operations are supported here.")
        if args.command == "approval-request":
            from .approval import validate_local_plan
            from .approval_window import approval_request
            validate_local_plan(plan)
            return envelope({"approval_request": approval_request(plan), "status": "not_authorized", "plan": plan.data, "reason": "Request only; a separate administrator must issue the approval window. CLI plans expire 300 seconds (five minutes) after creation; complete review, grant issuance and apply before expires_at. If review takes longer, create a new plan with a new hash and obtain a new grant."}, freshness="not_collected")
        if args.command == "plan-show":
            return envelope({"plan": plan.data, "phase": state["phase"]}, freshness="not_collected")
        if args.command == "apply":
            from .transport import TransportConfig
            TransportConfig.from_auth(load_config()).require_secure_write()
            if state.get("phase") != "planned":
                raise RouterError("replay_blocked_verify_first", "This plan was already applied; use verify to inspect its outcome.")
            if operation in PARENTAL_OPERATIONS:
                # Authenticate the complete private/public binding locally before
                # displaying an operator review; no router/keyring read is needed.
                from .native_parental_backend import NativeParentalBackend
                with state_lock(directory):
                    validator = NativeParentalBackend(None, None, fingerprint_key=private_read(directory / "alias.key"), state_dir=directory)
                    with validator.transaction():
                        validator.attach_plan(plan)
            elif operation in EXPANSION_OPERATIONS:
                from .expansion_backend import ExpansionBackend
                with state_lock(directory):
                    validator = ExpansionBackend(None, None, operation=operation, fingerprint_key=private_read(directory / 'alias.key'))
                    with validator.transaction():
                        validator.attach_plan(plan)
            # No root lock or credential is held while the operator decides.
            approval = confirm_plan(plan, window_id=args.window)
    directory, engine = _engine(operation) if operation in BOUND_OPERATIONS else _engine()
    with state_lock(directory):
        if args.command == "plan":
            plan = engine.plan(operation,intent)
            return envelope({"plan": plan.data, "phase": "planned"}, freshness="unknown")
        if args.command == "rollback":
            plan = engine.rollback_plan(args.plan_id)
            return envelope({"plan": plan.data, "phase": "planned", "reason": "Reverse preview only; a separate administrator grant, human confirmation and HTTPS apply are required."}, freshness="unknown")
        if args.command == "apply":
            result = engine.apply(args.plan_id, approval)
            if result["phase"] in {"apply_unverified", "outcome_unknown"}:
                result = engine.verify(args.plan_id)
        else:
            result = engine.verify(args.plan_id)
    return envelope(result, freshness="verified" if result["phase"] in {"verified", "verified_noop"} else "unknown")


def execute(args):
    if args.command == "traffic":
        _validate_traffic_args(args)
        return asyncio.run(_collect_traffic(args.kind, args.node, peer_alias=args.peer, band=args.band, backhaul=args.backhaul))
    if args.command in {"plan", "plan-show", "approval-request", "apply", "verify", "rollback"}:
        try:
            return _execute_operation(args)
        except FileNotFoundError as exc:
            raise RouterError("plan_not_found", "Stored plan was not found.") from exc
        except ValueError as exc:
            code = str(exc) if str(exc) in OPERATION_ERRORS else "invalid_operation"
            raise RouterError(code, "Operation was rejected; inspect the stored plan and current state.") from exc
    if args.command == "auth":
        if args.auth_command == "probe":
            result = asyncio.run(_collect([], probe=True))
            return envelope(result, source="native", freshness="unknown", fetched_at=result.get("fetched_at"))
        result = init_auth(args.host, args.username, allow_plain_http=args.allow_plain_http, ca_file=args.ca_file) if args.auth_command == "init" else auth_status()
        return envelope(result, freshness="not_collected")
    if args.command == "capabilities":
        if not 1 <= args.limit <= 20 or args.offset < 0:
            raise RouterError("invalid_arguments", "Capability limit must be 1..20 and offset nonnegative.", 2)
        if args.webui is None and any(value is not None for value in (args.family, args.status, args.blocker)):
            raise RouterError('invalid_arguments', 'WebUI filters require --webui.', 2)
        if args.webui is not None:
            from .webui_operations import load_webui_operations
            return load_webui_operations().page(None if args.webui == 'all' else args.webui,
                                               family=args.family, status=args.status, blocker=args.blocker,
                                               offset=args.offset, limit=args.limit)
        if args.native is not None:
            from .native_audit import load_native_audit
            return load_native_audit().page(None if args.native == "all" else args.native, offset=args.offset, limit=args.limit)
        if args.expansion is not None:
            from .expansion_manifest import page
            return page(None if args.expansion == 'all' else args.expansion, offset=args.offset, limit=args.limit)
        from .catalog import load_catalog
        catalog = load_catalog()
        from .transport import GROUPS
        # Catalog is checked-in application data, never a router response.
        manifest = catalog.manifest()
        if not 1 <= args.limit <= 20 or args.offset < 0:
            raise RouterError("invalid_arguments", "Capability limit must be 1..20 and offset nonnegative.", 2)
        pages = manifest["pages"]
        if args.group is None:
            counts = {}
            for page in pages:
                counts[page["status"]] = counts.get(page["status"], 0) + 1
            data = {"pages": len(pages), "placeholder_actions": sum(len(p["actions"]) for p in pages), "action_denominator": "unknown", "statuses": counts, "groups": sorted({p["group"] for p in pages}), "native_reads": [*GROUPS, *PROTECTED_GROUPS], "native_write_operations": [{"name":op["name"],"status":"implemented_live_unverified","backup_required":op['backup_required'],"approval":"exact-plan administrator grant, interactive human confirmation and verified HTTPS; backup-required controls also need verified configuration recovery"} for op in manifest["operations"] if not op["offline_only"]], "native_read_limits": {"vpn": "slot status only; protocol, route assignment and effective egress are unverified", "compatibility": "implemented commands; current-device support requires a bounded read"}}
        else:
            pages = [p for p in pages if p["group"] == args.group]
            if not pages:
                raise RouterError("unsupported_group", "Unknown catalog group.")
            selected = pages[args.offset:args.offset + args.limit]
            data = {"pages": [{"page":p["page"], "status":p["status"], "actions":[{"name":a["name"], "status":a["status"]} for a in p["actions"]], "gaps":p["gaps"]} for p in selected], "pagination": {"total": len(pages), "next_offset": args.offset + args.limit if args.offset + args.limit < len(pages) else None}}
        return {"schema_version": 1, "source": "offline_catalog", "observed_at": None, "freshness": "not_collected", "catalog_hash": catalog.hash, "data": data, "capability_gaps": ["Live firmware support and WebUI parity remain unverified."]}
    if args.command == "snapshot" and args.list:
        return envelope({"snapshots": SnapshotStore().list()}, freshness="not_collected")
    if args.command == "diff":
        result = envelope(SnapshotStore().diff(args.since, args.to, offset=args.offset, limit=args.limit), freshness="not_collected")
        return pack(result, minimum_rows=2) if args.format == "table" else result
    if args.command == "clients" and (not 1 <= args.limit <= 100 or args.offset < 0):
        raise RouterError("invalid_arguments", "Client limit must be 1..100 and offset nonnegative.", 2)
    if args.command == "clients" and args.alias is not None and re.fullmatch(r"client-[0-9a-f]{16}", args.alias) is None:
        raise RouterError("invalid_arguments", "Client alias must be client- followed by 16 lowercase hex digits.", 2)
    if args.command == "get" and len(args.group) != len(set(args.group)):
        raise RouterError("invalid_arguments", "Get groups must be distinct named groups.", 2)
    groups = args.group if args.command == "get" else (["clients"] if args.command == "clients" else ["identity", "wan", "cpu", "ram"])
    note_options = args.command == "get" and (args.note_offset is not None or args.note_limit is not None)
    if note_options:
        note_offset = 0 if args.note_offset is None else args.note_offset
        note_limit = 2048 if args.note_limit is None else args.note_limit
        if args.group != ["firmware_note"] or not 0 <= note_offset <= 131072 or not 1 <= note_limit <= 4096:
            raise RouterError("invalid_arguments", "Note pagination requires firmware_note alone, offset 0..131072 and limit 1..4096.", 2)
        result = asyncio.run(_collect(groups, note_offset=note_offset, note_limit=note_limit))
    else:
        result = asyncio.run(_collect(groups))
    if args.command == "clients":
        # Collector structure is selected explicitly once the upstream source returns.
        clients = result.get("data", {}).get("clients")
        if isinstance(clients, list):
            total_known = len(clients)
            if args.online:
                clients = [client for client in clients if isinstance(client, dict) and client.get("online") is True]
            if args.alias is not None:
                clients = [client for client in clients if isinstance(client, dict) and client.get("alias") == args.alias]
            result["data"]["clients"] = clients[args.offset:args.offset + args.limit]
            result["pagination"] = {"offset": args.offset, "limit": args.limit, "total": len(clients), "total_known": total_known, "next_offset": args.offset + args.limit if args.offset + args.limit < len(clients) else None}
    if args.command == "snapshot":
        from .catalog import load_catalog
        identity = result.get("data", {}).get("identity", {})
        if not isinstance(identity, dict) or not identity.get("device_fingerprint") or not identity.get("firmware"):
            raise RouterError("identity_unavailable", "A snapshot requires verified device and firmware identity.")
        record = SnapshotStore().save(result, {"schema": 1, "device": identity["device_fingerprint"], "firmware": identity["firmware"], "catalog": load_catalog().hash})
        result["snapshot_id"] = record["snapshot_id"]
    return result


def main(argv=None):
    try:
        result = execute(parser().parse_args(argv))
        emit(result)
        phase = result.get("data", {}).get("phase")
        return 1 if phase in {"apply_unverified", "outcome_unknown", "verification_failed"} else 0
    except RouterError as exc:
        emit({"error": {"code": exc.code, "message": exc.public_message}})
        return exc.exit_code
    except KeyboardInterrupt:
        emit({"error": {"code": "interrupted", "message": "Command interrupted."}})
        return 130
    except Exception:
        emit({"error": {"code": "internal_error", "message": "Command failed; no router health conclusion is available."}})
        return 1
