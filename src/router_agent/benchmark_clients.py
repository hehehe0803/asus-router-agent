"""Actual offline CLI task benchmark: paginated search versus exact alias filter."""
import argparse
import contextlib
import copy
import hashlib
from importlib.metadata import version
import io
import json
from pathlib import Path
import sys
from unittest.mock import patch

from . import cli
from .benchmark_contract import FETCHED_AT, ARCHIVAL, fixture_contract, archive_contract, validate_registered, archival_notice


def capture(argv, source=None):
    async def collect(*args, **kwargs):
        if source is None:
            raise AssertionError("No collection expected")
        return copy.deepcopy(source)

    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(cli, "_collect", collect), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = exc.code
    if ARCHIVAL.get() and code == 0 and "--help" not in argv:
        value = fixture_contract(json.loads(stdout.getvalue()))
        stdout = io.StringIO(json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n")
    return {"command": "router-agent " + " ".join(argv) + "\n", "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(), "exit_code": code}


def fixture(task):
    result = {"schema_version": 1, "data": {"identity": {"device_fingerprint": "synthetic-device-v2", "model": "RT-AX86U", "firmware": "synthetic-v2"},
                     "clients": [{"alias": f"client-{i:016x}", "online": None if i == task["target_index"] else i % 3 != 0,
                                  "connection": "wired" if i % 2 == 0 else "wireless",
                                  "signal_dbm": None if i % 2 == 0 else -40-i} for i in range(task["count"])]},
            "source": "native", "observed_at": None, "freshness": "unknown",
            "sources": {"identity": {"observed_at": None, "freshness": "unknown", "reason": "source_observation_time_unavailable"},
                        "clients": {"observed_at": None, "freshness": "unknown", "reason": "router_cached"}},
            "capability_gaps": ["Synthetic router-cached records; no live freshness evidence."],
            "warnings": ["logout_unconfirmed"]}
    result['fetched_at'] = FETCHED_AT
    for source in result['sources'].values():
        source['fetched_at'] = FETCHED_AT
    return fixture_contract(result)


def answer(task, steps):
    records = []
    metadata = None
    alias = f"client-{task['target_index']:016x}"
    total_known = None
    for step in steps:
        if step["exit_code"] != 0:
            raise ValueError("CLI task failed")
        value = json.loads(step["stdout"])
        current = {k: v for k, v in value.items() if k not in {"data", "pagination"}}
        current["identity"] = value["data"]["identity"]
        if metadata is not None and current != metadata:
            raise ValueError("Metadata changed between pages")
        metadata = current
        page = value["pagination"]
        if total_known is not None and page["total_known"] != total_known:
            raise ValueError("Total known changed between pages")
        total_known = page["total_known"]
        records.extend(client for client in value["data"]["clients"] if client["alias"] == alias)
    return {"requested_alias": alias, "clients": records, "match_count": len(records),
            "total_known": total_known, "metadata": metadata}


def execute_task(task):
    source = fixture(task)
    baseline = [capture(["clients", "--limit", "10"] + (["--offset", str(offset)] if offset else []), source)
                for offset in range(0, task["count"], 10)]
    filtered = [capture(["clients", "--alias", f"client-{task['target_index']:016x}"], source)]
    return {"paginated_search": baseline, "exact_alias": filtered}


def validate_answer(task, candidate, transcript):
    actual = answer(task, transcript)
    if json.dumps(actual, sort_keys=True) != json.dumps(task["required_answer"], sort_keys=True):
        raise ValueError(f"Required answer lost: {task['id']} {candidate}")
    if candidate == "exact_alias" and json.loads(transcript[0]["stdout"])["pagination"]["total"] != actual["match_count"]:
        raise ValueError("Filtered match count is inconsistent")


def _freeze(schema_version=8):
    # Cases and required answer semantics are fixed before scoring any candidate.
    tasks = [{"id": "target_client_training", "split": "train", "count": 20, "target_index": 15},
             {"id": "target_client_heldout", "split": "heldout", "count": 35, "target_index": 31}]
    discovery = [capture(["--help"]), capture(["clients", "--help"])]
    for task in tasks:
        source = fixture(task)
        alias = f"client-{task['target_index']:016x}"
        metadata = {k: v for k, v in source.items() if k != "data"}
        metadata["identity"] = source["data"]["identity"]
        task["required_answer"] = {"requested_alias": alias,
                                   "clients": [c for c in source["data"]["clients"] if c["alias"] == alias],
                                   "match_count": 1, "total_known": task["count"], "metadata": metadata}
        task["transcripts"] = execute_task(task)
    return {"schema_version": schema_version, "provenance": "Actual CLI main with injected synthetic collector; no live credentials or router calls.",
            "discovery": discovery, "tasks": tasks}


def freeze(schema_version=8, historical_schema=False):
    with archive_contract(historical_schema):
        return _freeze(schema_version)


def measure(steps, discovery, query, encoding):
    parts = {"commands": [s["command"] for s in discovery + steps],
             "stdout": [s["stdout"] for s in discovery + steps],
             "stderr": [s["stderr"] for s in discovery + steps], "task_instructions": [query]}
    tokens = {k: sum(len(encoding.encode(v)) for v in values) for k, values in parts.items()}
    sizes = {k: sum(len(v.encode()) for v in values) for k, values in parts.items()}
    return {"tokens": sum(tokens.values()), "bytes": sum(sizes.values()), "response_calls": len(steps),
            "discovery_calls": len(discovery), "component_tokens": tokens, "component_bytes": sizes}


def run(path, encoding_name="o200k_base", historical_help=False, historical_schema=False):
    import tiktoken
    raw = Path(path).read_bytes()
    corpus = json.loads(raw)
    # Regenerate every transcript from actual current CLI behavior. Drift is an error,
    # rather than silently trusting archived hand-authored response counts.
    if corpus.get("schema_version") not in {2, 3, 4, 5, 6, 7, 8}:
        raise ValueError("Unsupported client benchmark corpus")
    if historical_schema:
        validate_registered(raw)
    current = freeze(schema_version=corpus["schema_version"], historical_schema=historical_schema)
    if historical_help:
        # Archive only discovery text. Required answers and response transcripts
        # must still match actual current CLI execution with injected fixtures.
        matches = corpus["tasks"] == current["tasks"]
        matches &= [(step["command"], step["exit_code"]) for step in corpus["discovery"]] == [(step["command"], step["exit_code"]) for step in current["discovery"]]
    else:
        matches = corpus == current
    if not matches:
        raise ValueError("Current CLI behavior differs from frozen client corpus")
    encoding = tiktoken.get_encoding(encoding_name)
    rows = []
    for task in corpus["tasks"]:
        scores = {}
        query = f"Find the full selected record for local alias client-{task['target_index']:016x}; preserve identity, source, freshness, gaps, warnings, total known and explicit match count.\n"
        for candidate, transcript in task["transcripts"].items():
            validate_answer(task, candidate, transcript)
            scores[candidate] = measure(transcript, corpus["discovery"], query, encoding)
        baseline, filtered = scores["paginated_search"], scores["exact_alias"]
        rows.append({"task": task["id"], "split": task["split"], "required_answer_valid": True,
                     "candidates": scores, "saved_tokens": baseline["tokens"] - filtered["tokens"],
                     "saved_percent": round(100 * (baseline["tokens"] - filtered["tokens"]) / baseline["tokens"], 2)})
    train = next(row for row in rows if row["split"] == "train")
    chosen = "exact_alias" if train["saved_tokens"] > 0 else "paginated_search"
    heldout = next(row for row in rows if row["split"] == "heldout")
    return {"schema_version": corpus["schema_version"], "corpus_sha256": hashlib.sha256(raw).hexdigest(),
            "tokenizer": {"package": "tiktoken", "version": version("tiktoken"), "encoding": encoding_name,
                          "claim": "proxy only; not GPT-6/GPT-6.1 tokens or billing"},
            "selected_on_training": chosen, "heldout_gate": "passed" if chosen == "paginated_search" or heldout["saved_tokens"] >= 0 else "rejected_token_regression",
            "browser_baseline": "unavailable; no browser savings claim", "tasks": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=None)
    parser.add_argument("--freeze", action="store_true", help="Write a current-help synthetic v7 corpus before scoring")
    parser.add_argument("--historical-help", action="store_true", help="Use archived discovery help; still replay current response behavior")
    parser.add_argument("--historical-schema", action="store_true", help="Explicit registered pre-fetched_at fixture contract; no current reply parity")
    args = parser.parse_args(argv)
    if args.historical_schema and (args.corpus is None or args.freeze):
        parser.error("Historical schema requires explicit corpus and cannot freeze")
    if args.freeze:
        if args.historical_help:
            parser.error("--freeze cannot be combined with historical help")
        Path(args.corpus or "benchmarks/corpus-v8-clients.json").write_text(json.dumps(freeze(schema_version=8), indent=2) + "\n")
    else:
        if args.historical_schema:
            print(archival_notice(), file=sys.stderr)
        elif args.historical_help:
            print("Historical replay: archived discovery help; response transcripts still verified against current CLI. Not current discovery-cost evidence.", file=sys.stderr)
        print(json.dumps(run(args.corpus or "benchmarks/corpus-v8-clients.json", historical_help=args.historical_help, historical_schema=args.historical_schema), indent=2))


if __name__ == "__main__":
    main()
