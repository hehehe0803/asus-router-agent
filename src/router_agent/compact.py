"""Opt-in, lossless JSON row compaction; callers must sanitize data first.

This codec does not authorize operations or discard fields. It is deliberately
separate from the default CLI output until consumer compatibility is established.
"""
import json

TABLE_HELP = 'Compact rows: {"$table":[columns,rows]} represents a list of objects; zip each row with columns. {"$object":[[key,value],...]} escapes an object containing reserved keys. Null, freshness, gaps and approval meaning are unchanged.\n'
RESERVED = {"$table", "$object"}


def pack(value, *, minimum_rows=2):
    if minimum_rows < 2:
        raise ValueError("minimum_rows must be at least two")
    if isinstance(value, dict):
        if RESERVED.intersection(value):
            return {"$object": [[k, pack(v, minimum_rows=minimum_rows)] for k, v in value.items()]}
        return {k: pack(v, minimum_rows=minimum_rows) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) >= minimum_rows and all(isinstance(v, dict) for v in value):
            columns = list(value[0])
            if columns and all(set(v) == set(columns) for v in value):
                return {"$table": [columns, [[pack(v[k], minimum_rows=minimum_rows) for k in columns] for v in value]]}
        return [pack(v, minimum_rows=minimum_rows) for v in value]
    return value


def unpack(value):
    if isinstance(value, dict):
        if set(value) == {"$table"}:
            columns, rows = value["$table"]
            if not isinstance(columns, list) or not all(isinstance(k, str) for k in columns) or len(set(columns)) != len(columns):
                raise ValueError("invalid columns")
            if not isinstance(rows, list) or any(not isinstance(row, list) or len(row) != len(columns) for row in rows):
                raise ValueError("invalid rows")
            return [{k: unpack(v) for k, v in zip(columns, row)} for row in rows]
        if set(value) == {"$object"}:
            pairs = value["$object"]
            if not isinstance(pairs, list) or any(not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str) for pair in pairs):
                raise ValueError("invalid escaped object")
            if len({pair[0] for pair in pairs}) != len(pairs):
                raise ValueError("duplicate escaped key")
            return {k: unpack(v) for k, v in pairs}
        return {k: unpack(v) for k, v in value.items()}
    if isinstance(value, list):
        return [unpack(v) for v in value]
    return value


def compact_json(value, *, minimum_rows=2):
    return json.dumps(pack(value, minimum_rows=minimum_rows), separators=(",", ":"), ensure_ascii=True, allow_nan=False)
