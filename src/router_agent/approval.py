"""Approval comes from a human operating an interactive terminal, never a hash alone."""
import hashlib
import math
import sys
import time
from .catalog import canonical
from .errors import RouterError
from .operations import ApprovedScope, PLAN_KEYS, PARENTAL_PLAN_KEYS, PARENTAL_OPERATIONS, EXPANSION_OPERATIONS, BOUND_OPERATIONS


def validate_local_plan(plan, *, clock=time.time):
    data = plan.data
    parental=data.get("operation") in BOUND_OPERATIONS
    if set(data) != (PARENTAL_PLAN_KEYS if parental else PLAN_KEYS):
        raise RouterError("invalid_plan", "Stored plan structure is invalid.")
    unsigned = {k:v for k,v in data.items() if k != "hash"}
    if hashlib.sha256(canonical(unsigned).encode()).hexdigest() != data["hash"]:
        raise RouterError("invalid_plan", "Stored plan hash does not match its content.")
    if data.get('operation') in EXPANSION_OPERATIONS:
        from .expansion_backend import validate_public_context
        validate_public_context(data)
    elif parental:
        import re
        if data["fields"] != ["policy_fingerprint"] or any(not isinstance(data[k],dict) or set(data[k]) != {"policy_fingerprint"} or not isinstance(data[k]["policy_fingerprint"],str) or not re.fullmatch(r"[0-9a-f]{64}",data[k]["policy_fingerprint"]) for k in ("before","after","verification")):
            raise RouterError("invalid_plan", "Stored parental policy scope is invalid.")
        if (not isinstance(data["context_binding"],str) or not re.fullmatch(r"[0-9a-f]{64}",data["context_binding"])
                or not isinstance(data["review"],dict) or set(data["review"])!={"before","after","preservation"}
                or not isinstance(data["intent"],dict) or not isinstance(data["side_effects"],list)
                or "firewall_restart" not in data["side_effects"]):
            raise RouterError("invalid_plan", "Stored parental review or context binding is invalid.")
        action=data["intent"].get("action")
        if action == "restore_rules":
            if data["operation"]!="parental.rule" or set(data["intent"])!={"action","source_plan","client_alias"} or not re.fullmatch(r"[0-9a-f]{64}",data["intent"].get("source_plan", "")) or not re.fullmatch(r"client-[0-9a-f]{16}",data["intent"].get("client_alias", "")):
                raise RouterError("invalid_plan", "Stored parental recovery intent is invalid.")
        else:
            from .native_parental_backend import validate_parental_intent
            expected={"parental.enable":"enable","parental.block_all":"block_all","parental.rule":"rule"}[data["operation"]]
            if action!=expected:
                raise RouterError("invalid_plan", "Stored parental operation intent is invalid.")
            original={k:v for k,v in data["intent"].items() if k not in {"action","source_plan"}}
            validate_parental_intent(data["operation"],original)
            if "source_plan" in data["intent"] and not re.fullmatch(r"[0-9a-f]{64}",data["intent"]["source_plan"]):
                raise RouterError("invalid_plan", "Stored parental recovery identity is invalid.")
        if data["operation"]=="parental.block_all" and "all_client_internet_blocking_setting" not in data["side_effects"]:
            raise RouterError("invalid_plan", "Block-all requires explicit all-client internet blocking scope.")
    elif data["operation"] != "led.set" or data["fields"] != ["enabled"] or any(not isinstance(data[k],dict) or set(data[k]) != {"enabled"} or type(data[k]["enabled"]) is not bool for k in ("before","after","verification")):
        raise RouterError("unsupported_operation", "Only finite named native operations are supported here.")
    if data['after'] != data['verification']:
        raise RouterError("invalid_plan", "Stored verification scope is invalid.")
    for field in ('device','firmware','catalog_hash','risk'):
        if not isinstance(data[field],str) or not data[field] or any(ord(c)<32 for c in data[field]):
            raise RouterError("invalid_plan", "Stored plan identity is invalid.")
    if any(type(data[k]) not in (int,float) or not math.isfinite(data[k]) for k in ('created_at','expires_at')) or not data['created_at'] <= clock() < data['expires_at']:
        raise RouterError("expired_plan", "Plan is expired or not yet valid; create a new plan.")
    return data


def confirm_plan(plan, *, window_id=None, clock=time.time, input_reader=None):
    data = validate_local_plan(plan, clock=clock)
    from .approval_window import validate_window
    validate_window(plan, window_id, clock=clock)
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise RouterError("human_confirmation_required", "Apply requires a human operating an interactive terminal.")
    keys=("hash","device","firmware","operation","before","after","risk","expires_at")
    if data["operation"] in BOUND_OPERATIONS:keys+=("review","intent","side_effects")
    print("Review exact native plan: " + canonical({key:data[key] for key in keys}),file=sys.stderr)
    phrase = "apply " + plan.id
    try:
        print("Type " + phrase + " to authorize this exact change: ", file=sys.stderr, end="", flush=True)
        reply = (input_reader or input)("")
    except (EOFError,KeyboardInterrupt) as exc:
        raise RouterError("approval_cancelled", "Human confirmation was cancelled.") from exc
    if reply != phrase:
        raise RouterError("approval_cancelled", "Human confirmation was cancelled.")
    data = validate_local_plan(plan,clock=clock)
    return validate_window(plan, window_id, clock=clock)
