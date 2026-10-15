"""Strict coverage inventory. Inventory entries are not implemented operations."""
from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from typing import Any

STATUSES = {"inventory_only", "contract_verified", "implemented", "live_verified", "unsupported", "human_handoff"}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def exact_keys(value: dict, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("invalid_structure")


class Catalog:
    def __init__(self, data: dict):
        exact_keys(data, {"schema_version", "pages", "operations"})
        if data["schema_version"] != 1 or not isinstance(data["pages"], list) or not isinstance(data["operations"], list):
            raise ValueError("invalid_catalog")
        seen = set()
        for page in data["pages"]:
            exact_keys(page, {"group", "page", "url", "status", "actions", "gaps"})
            if not isinstance(page["group"], str) or not isinstance(page["page"], str) or page["status"] not in STATUSES:
                raise ValueError("invalid_page")
            if page["url"] is not None and not isinstance(page["url"], str):
                raise ValueError("invalid_url")
            if not isinstance(page["gaps"], list) or not all(isinstance(x, str) for x in page["gaps"]):
                raise ValueError("invalid_gaps")
            if not isinstance(page["actions"], list):
                raise ValueError("invalid_actions")
            key = (page["group"], page["page"])
            if key in seen:
                raise ValueError("duplicate_page")
            seen.add(key)
            for action in page["actions"]:
                exact_keys(action, {"id", "name", "status", "firmware", "input_schema", "secret_fields", "evidence", "side_effects", "transport", "verification", "recovery"})
                if not isinstance(action["name"], str) or action["status"] not in STATUSES:
                    raise ValueError("invalid_action")
        names = set()
        for op in data["operations"]:
            exact_keys(op, {"name", "status", "source", "fields", "risk", "backup_required", "offline_only"})
            if op["name"] in names or op["status"] not in {"contract_verified", "implemented", "live_verified"}:
                raise ValueError("invalid_operation")
            names.add(op["name"])
            if op["risk"] not in {"low", "critical", "exposure", "disruptive"} or type(op["backup_required"]) is not bool or type(op["offline_only"]) is not bool:
                raise ValueError("invalid_operation_policy")
            if not isinstance(op["source"], str) or not isinstance(op["fields"], dict) or not op["fields"]:
                raise ValueError("invalid_fields")
            for name, spec in op["fields"].items():
                exact_keys(spec, {"type", "secret"})
                if not isinstance(name, str) or spec["type"] not in {"bool", "int", "str"} or type(spec["secret"]) is not bool:
                    raise ValueError("invalid_field")
        self._json = canonical(data)
        self.hash = hashlib.sha256(self._json.encode()).hexdigest()

    def manifest(self) -> dict:
        return json.loads(self._json)

    def operation(self, name: str) -> dict:
        for op in self.manifest()["operations"]:
            if op["name"] == name:
                return op
        raise ValueError("unsupported_operation")


def load_catalog(path=None) -> Catalog:
    source = files("router_agent").joinpath("data/catalog.json") if path is None else path
    if isinstance(source, str):
        from pathlib import Path
        source = Path(source)
    return Catalog(json.loads(source.read_text(encoding="utf-8")))
