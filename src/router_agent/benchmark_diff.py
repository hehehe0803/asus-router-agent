"""Offline all-changes diff task: actual compact CLI versus experimental codec."""
import argparse
import copy
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from . import cli
from .benchmark_contract import archive_contract, validate_registered, archival_notice
from .benchmark import dumps, measure_task
from .benchmark_clients import capture
from .compact import pack, unpack
from .snapshots import SnapshotStore

CANDIDATES = ("compact_json", "table_2", "table_4", "table_8")
SYNTHETIC_IDS = ("43a15c927bfd4e508693feac2170d854", "8e24bda4a17549c68031fc827596d0ea")


def leaves(value, path=""):
    if isinstance(value, dict) and value:
        return [fact for key, child in value.items() for fact in leaves(child, path + "/" + key.replace("~", "~0").replace("/", "~1"))]
    if isinstance(value, list) and value:
        return [fact for i, child in enumerate(value) for fact in leaves(child, path + "/" + str(i))]
    return [{"path": path, "value": value}]


def collect_pages(store, before, after, output_format=None):
    steps, changes, offset = [], [], 0
    with patch.object(cli, "SnapshotStore", lambda: store):
        while True:
            argv = ["diff", "--since", before, "--to", after, "--offset", str(offset), "--limit", "20"]
            if output_format is not None:
                argv += ["--format", output_format]
            step = capture(argv)
            payload = json.loads(step["stdout"])
            if dumps(payload) != step["stdout"]:
                raise ValueError("Actual CLI serialization differs from measured compact JSON")
            if step["exit_code"] != 0:
                raise ValueError("Synthetic diff command failed")
            steps.append(dict(step, command=step["command"].removesuffix("\n"), stdout=payload))
            data = (unpack(payload) if output_format == "table" else payload)["data"]
            changes.extend(data["changes"])
            next_offset = data["pagination"]["next_offset"]
            if next_offset is None:
                if len(changes) != data["total_changes"]:
                    raise ValueError("Pagination lost changes")
                break
            if next_offset <= offset:
                raise ValueError("Pagination did not advance")
            offset = next_offset
    return steps, changes


def execute_case(case, include_table=False):
    identity = {"schema": 1, "device": "synthetic-diff-device", "firmware": "synthetic-diff-v1", "catalog": "synthetic-catalog"}
    with tempfile.TemporaryDirectory() as directory:
        store = SnapshotStore(directory)
        if case["kind"] == "clients":
            before = {"config": {"clients": [{"alias": f"client-{i:016x}", "online": False, "signal_dbm": None if case["split"] == "train" else -60-i} for i in range(case["count"])]}}
            after = copy.deepcopy(before)
            for i, client in enumerate(after["config"]["clients"]):
                client["signal_dbm"] = -50-i if case["split"] == "train" else None
        else:
            before = {"config": {"enabled": None, "sources": ["unknown", "synthetic"], "default_route": False}}
            after = {"config": {"hostname": None, "sources": ["synthetic", "unknown"], "default_route": None}}
        with patch("router_agent.snapshots.uuid.uuid4", side_effect=[SimpleNamespace(hex=value) for value in SYNTHETIC_IDS]):
            old = store.save(before, identity, kind="config")
            new = store.save(after, identity, kind="config")
        steps, changes = collect_pages(store, old["snapshot_id"], new["snapshot_id"])
        # Independently derive each expected change from the synthetic input.
        if case["kind"] == "clients":
            expected = [{"path": f"/config/clients/{i}/signal_dbm", "before": before["config"]["clients"][i]["signal_dbm"], "after": after["config"]["clients"][i]["signal_dbm"]} for i in range(case["count"])]
        else:
            expected = [
                {"path": "/config/default_route", "before": False, "after": None},
                {"path": "/config/enabled", "before": None, "after": None, "before_present": True, "after_present": False},
                {"path": "/config/hostname", "before": None, "after": None, "before_present": False, "after_present": True},
                {"path": "/config/sources/0", "before": "unknown", "after": "synthetic"},
                {"path": "/config/sources/1", "before": "synthetic", "after": "unknown"},
            ]
        if dumps(changes) != dumps(expected):
            raise ValueError("Real store did not preserve expected null/presence/array changes")
        result = dict(case, steps=steps, expected_changes=expected, required_facts=leaves(steps))
        if include_table:
            table_steps, table_changes = collect_pages(store, old["snapshot_id"], new["snapshot_id"], output_format="table")
            if dumps(table_changes) != dumps(expected):
                raise ValueError("Actual CLI table mode lost expected changes")
            for ordinary, compact in zip(steps, table_steps, strict=True):
                if dumps(ordinary["stdout"]) != dumps(unpack(compact["stdout"])) or ordinary["exit_code"] != compact["exit_code"] or ordinary["stderr"] != compact["stderr"]:
                    raise ValueError("Actual table mode changed full response facts")
            result["table_steps"] = table_steps
        return result


def freeze():
    # Freeze cases before any scoring; held-out cases have a different population
    # and different null direction, plus an independent presence/array case.
    cases = [{"id": "all_changes_train_35", "split": "train", "kind": "clients", "count": 35},
             {"id": "all_changes_heldout_27", "split": "heldout", "kind": "clients", "count": 27},
             {"id": "heldout_presence_null_arrays", "split": "heldout", "kind": "presence", "count": 5}]
    discovery = [capture(["--help"]), capture(["diff", "--help"])]
    return {"schema_version": 1, "provenance": "Real temporary SnapshotStore and actual CLI main; synthetic compatible config snapshots only.",
            "discovery": discovery, "tasks": [execute_case(case) for case in cases]}


def _freeze_actual(schema_version=7):
    if schema_version not in {2,3,4,5,6,7}:
        raise ValueError("Unsupported actual CLI diff corpus")
    corpus = freeze()
    corpus["schema_version"] = schema_version
    corpus["provenance"] = "Actual CLI JSON and public --format table outputs over real temporary SnapshotStore synthetic compatible config snapshots."
    corpus["tasks"] = [execute_case({key: task[key] for key in ("id", "split", "kind", "count")}, include_table=True) for task in corpus["tasks"]]
    return corpus


def freeze_actual(schema_version=7, historical_schema=False):
    with archive_contract(historical_schema):
        return _freeze_actual(schema_version)


def run_actual(path, encoding_name="o200k_base", historical_help=False, historical_schema=False):
    import tiktoken
    raw = Path(path).read_bytes()
    corpus = json.loads(raw)
    if historical_schema:
        validate_registered(raw)
    current = freeze_actual(schema_version=corpus.get("schema_version"), historical_schema=historical_schema)
    if historical_help:
        if [(step["command"],step["exit_code"]) for step in corpus["discovery"]] != [(step["command"],step["exit_code"]) for step in current["discovery"]]:
            raise ValueError("Historical discovery commands differ from current CLI")
        current["discovery"] = corpus["discovery"]
    if corpus != current:
        raise ValueError("Actual CLI JSON/table behavior or discovery differs from frozen corpus")
    encoding = tiktoken.get_encoding(encoding_name)
    discovery = corpus["discovery"]
    discovery_tokens = sum(len(encoding.encode(step[key])) for step in discovery for key in ("command", "stdout", "stderr"))
    discovery_bytes = sum(len(step[key].encode()) for step in discovery for key in ("command", "stdout", "stderr"))
    results = {}
    for candidate, field in (("compact_json", "steps"), ("cli_table", "table_steps")):
        rows = []
        for task in corpus["tasks"]:
            steps = task[field]
            measured_task = {"id": task["id"], "split": task["split"], "steps": steps, "required_facts": leaves(steps)}
            # Table output is already the actual emitted wire representation.
            # The real diff --help contains TABLE_HELP, charged to both modes;
            # do not invent a second instruction charge.
            row = measure_task(measured_task, "compact_json", encoding, "")
            query = "Retrieve every semantic change between these compatible synthetic config snapshots, preserving paths, values, null/presence distinctions, pagination and unknown observation metadata.\n"
            row["component_tokens"].update(discovery=discovery_tokens, task_instructions=len(encoding.encode(query)))
            row["component_bytes"].update(discovery=discovery_bytes, task_instructions=len(query.encode()))
            row["tokens"] = sum(row["component_tokens"].values())
            row["bytes"] = sum(row["component_bytes"].values())
            row["discovery_calls"] = len(discovery)
            rows.append(row)
        results[candidate] = {"tasks": rows, "totals": {split: {key: sum(row[key] for row in rows if row["split"] == split) for key in ("tokens", "bytes", "calls")} for split in ("train", "heldout")}}
    selected = min(results, key=lambda candidate: results[candidate]["totals"]["train"]["tokens"])
    base, chosen = results["compact_json"]["totals"], results[selected]["totals"]
    return {"schema_version": corpus["schema_version"], "corpus_sha256": hashlib.sha256(raw).hexdigest(),
            "tokenizer": {"package": "tiktoken", "version": version("tiktoken"), "encoding": encoding_name, "claim": "proxy only; not GPT-6/GPT-6.1 tokens or billing"},
            "selected_on_training": selected, "heldout_gate": "passed" if chosen["heldout"]["tokens"] <= base["heldout"]["tokens"] else "rejected_token_regression",
            "runtime_default": "compact_json", "candidate_status": "implemented opt-in public diff --format table; full actual CLI transcript costs",
            "browser_baseline": "unavailable; no browser savings claim", "candidates": results,
            "savings_vs_compact_json": {split: {"tokens": base[split]["tokens"] - chosen[split]["tokens"], "percent": round(100 * (base[split]["tokens"] - chosen[split]["tokens"]) / base[split]["tokens"], 2)} for split in ("train", "heldout")}}


def validate_archived_pages(task):
    offset, total, recovered = 0, None, []
    for index, step in enumerate(task["steps"]):
        if step["exit_code"] != 0:
            raise ValueError("Archived diff task contains a failed response")
        data = step["stdout"]["data"]
        pagination = data["pagination"]
        limit = pagination["limit"]
        if not isinstance(limit, int) or not 1 <= limit <= 20 or pagination["offset"] != offset:
            raise ValueError("Archived pagination is invalid")
        if total is not None and total != data["total_changes"]:
            raise ValueError("Archived total changed across pages")
        total = data["total_changes"]
        if len(data["changes"]) > limit:
            raise ValueError("Archived page exceeds its bound")
        recovered.extend(data["changes"])
        expected_next = offset + limit if offset + limit < total else None
        if pagination["next_offset"] != expected_next:
            raise ValueError("Archived next offset is inconsistent")
        if expected_next is None and index != len(task["steps"]) - 1:
            raise ValueError("Archived pagination continues beyond completion")
        offset += limit
    if total != len(recovered) or dumps(recovered) != dumps(task["expected_changes"]):
        raise ValueError("Archived task does not preserve every expected change")


def run(path, encoding_name="o200k_base", historical_format_study=False):
    import tiktoken
    raw = Path(path).read_bytes()
    corpus = json.loads(raw)
    if corpus.get("schema_version") != 1 or not corpus.get("tasks"):
        raise ValueError("Historical format study requires a diff-v1 corpus")
    if not historical_format_study and corpus != freeze():
        raise ValueError("Current CLI diff behavior or discovery differs from frozen corpus")
    for task in corpus["tasks"]:
        if not task.get("required_facts") or task["split"] not in {"train", "heldout"}:
            raise ValueError("Archived task needs frozen facts and a valid split")
        validate_archived_pages(task)
    encoding = tiktoken.get_encoding(encoding_name)
    # Actual discovery stdout, stderr and commands are all charged, separated
    # per call so concatenation cannot create a token-count discount.
    discovery = corpus["discovery"]
    discovery_tokens = sum(len(encoding.encode(step[key])) for step in discovery for key in ("command", "stdout", "stderr"))
    discovery_bytes = sum(len(step[key].encode()) for step in discovery for key in ("command", "stdout", "stderr"))
    results = {}
    for candidate in CANDIDATES:
        rows = []
        for task in corpus["tasks"]:
            measured = measure_task(task, candidate, encoding, "")
            measured["tokens"] += discovery_tokens
            measured["bytes"] += discovery_bytes
            measured["component_tokens"]["discovery"] = discovery_tokens
            measured["component_bytes"]["discovery"] = discovery_bytes
            query = "Retrieve every semantic change between these compatible synthetic config snapshots, preserving paths, values, null/presence distinctions, pagination and unknown observation metadata.\n"
            measured["component_tokens"]["task_instructions"] = len(encoding.encode(query))
            measured["component_bytes"]["task_instructions"] = len(query.encode())
            measured["tokens"] += measured["component_tokens"]["task_instructions"]
            measured["bytes"] += measured["component_bytes"]["task_instructions"]
            measured["discovery_calls"] = len(discovery)
            recovered = []
            for step in task["steps"]:
                value = step["stdout"]
                restored = unpack(pack(value, minimum_rows=int(candidate.split("_")[1]))) if candidate.startswith("table_") else value
                recovered.extend(restored["data"]["changes"])
            if dumps(recovered) != dumps(task["expected_changes"]):
                raise ValueError("Candidate lost complete-task changes")
            rows.append(measured)
        results[candidate] = {"tasks": rows, "totals": {split: {key: sum(row[key] for row in rows if row["split"] == split) for key in ("tokens", "bytes", "calls")} for split in ("train", "heldout")}}
    selected = min(CANDIDATES, key=lambda candidate: results[candidate]["totals"]["train"]["tokens"])
    base, chosen = results["compact_json"]["totals"], results[selected]["totals"]
    accepted = chosen["heldout"]["tokens"] <= base["heldout"]["tokens"]
    return {"schema_version": 1, "corpus_sha256": hashlib.sha256(raw).hexdigest(),
            "tokenizer": {"package": "tiktoken", "version": version("tiktoken"), "encoding": encoding_name, "claim": "proxy only; not GPT-6/GPT-6.1 tokens or billing"},
            "selected_on_training": selected, "heldout_gate": "passed" if accepted else "rejected_token_regression",
            "runtime_default": "compact_json", "candidate_status": "experimental pure formatter; not public CLI output mode",
            "browser_baseline": "unavailable; no browser savings claim", "candidates": results,
            "savings_vs_compact_json": {split: {"tokens": base[split]["tokens"] - chosen[split]["tokens"], "percent": round(100 * (base[split]["tokens"] - chosen[split]["tokens"]) / base[split]["tokens"], 2)} for split in ("train", "heldout")}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus")
    parser.add_argument("--freeze", action="store_true")
    parser.add_argument("--historical-format-study", action="store_true", help="Replay archived diff-v1 formatter study; requires explicit --corpus")
    parser.add_argument("--historical-help", action="store_true", help="Replay archived actual-CLI discovery help; current replies/facts still checked")
    parser.add_argument("--historical-schema", action="store_true", help="Registered pre-fetched_at envelope contract; no current response parity")
    args = parser.parse_args(argv)
    if args.historical_schema and (args.corpus is None or args.freeze or args.historical_format_study):
        parser.error("Historical schema requires explicit corpus and cannot freeze or combine with format study")
    if args.historical_help and (args.corpus is None or args.freeze or args.historical_format_study):
        parser.error("Historical help requires explicit --corpus and cannot freeze or combine with format study")
    if args.historical_format_study:
        if args.corpus is None or args.freeze:
            parser.error("Historical replay requires explicit --corpus and cannot freeze")
        print("Historical format study only: archived synthetic transcripts and discovery, not current CLI behavior or current help costs.", file=sys.stderr)
        print(json.dumps(run(args.corpus, historical_format_study=True), indent=2))
    elif args.freeze:
        Path(args.corpus or "benchmarks/corpus-diff-v7.json").write_text(json.dumps(freeze_actual(), indent=2) + "\n")
    else:
        if args.historical_schema:
            print(archival_notice(), file=sys.stderr)
        elif args.historical_help:
            print("Historical discovery help replay; current JSON/table replies and required facts are still checked.", file=sys.stderr)
        print(json.dumps(run_actual(args.corpus or "benchmarks/corpus-diff-v7.json", historical_help=args.historical_help, historical_schema=args.historical_schema), indent=2))


if __name__ == "__main__":
    main()
