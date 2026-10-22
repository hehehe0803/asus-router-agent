"""Offline synthetic transcript benchmark, never a router/browser performance claim."""
import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import sys

from .benchmark_contract import FETCHED_AT
from .cli import parser as cli_parser
from .compact import TABLE_HELP, pack, unpack

CANDIDATES = ("readable_json", "compact_json", "table_2", "table_4", "table_8")


def dumps(value, pretty=False):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      **({"indent": 2} if pretty else {"separators": (",", ":")})) + "\n"


def pointer(value, path):
    for piece in path.lstrip("/").split("/") if path else []:
        key = piece.replace("~1", "/").replace("~0", "~")
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


def validate(task, decoded_steps):
    for fact in task["required_facts"]:
        actual = pointer(decoded_steps, fact["path"])
        # bool must not pass as 0/1, and unknown must not pass as healthy.
        if type(actual) is not type(fact["value"]) or actual != fact["value"]:
            raise ValueError(f"Required fact lost: {task['id']} {fact['path']}")
    if decoded_steps != task["steps"]:
        raise ValueError(f"Lossless round-trip failed: {task['id']}")


def measure_task(task, candidate, encoding, discovery_help):
    decoded, stdout, stderr, commands = [], [], [], []
    uses_table = False
    for step in task["steps"]:
        value = step["stdout"]
        wire = pack(value, minimum_rows=int(candidate.split("_")[1])) if candidate.startswith("table_") else value
        encoded = dumps(wire, pretty=candidate == "readable_json")
        restored = unpack(json.loads(encoded)) if candidate.startswith("table_") else json.loads(encoded)
        # Codec instructions are charged once per task, only when JSON actually changes.
        uses_table |= wire != value
        decoded.append(dict(step, stdout=restored))
        stdout.append(encoded)
        stderr.append(step["stderr"])
        commands.append(step["command"] + "\n")
    validate(task, decoded)
    components = {"help_instructions": [discovery_help] + ([TABLE_HELP] if uses_table else []),
                  "commands": commands, "stdout": stdout, "stderr": stderr}
    # Each stream/call is counted separately, avoiding savings at concatenation boundaries.
    tokens = {k: sum(len(encoding.encode(s)) for s in parts) for k, parts in components.items()}
    sizes = {k: sum(len(s.encode("utf-8")) for s in parts) for k, parts in components.items()}
    return {"task": task["id"], "split": task["split"], "valid": True,
            "calls": len(task["steps"]), "tokens": sum(tokens.values()), "bytes": sum(sizes.values()),
            "component_tokens": tokens, "component_bytes": sizes}


def freeze(schema_version=3):
    """Refresh the synthetic formatter study, never actual CLI coverage evidence."""
    from .benchmark_diff import leaves
    corpus = json.loads((Path(__file__).resolve().parents[2] / "benchmarks/corpus-v1.json").read_text())
    corpus['schema_version'] = schema_version
    corpus['provenance'] = 'Synthetic formatter study with full fetched_at metadata; not an actual collector or CLI task benchmark.'
    for task in corpus['tasks']:
        for step in task['steps']:
            value = step['stdout']
            if 'error' not in value:
                value['fetched_at'] = FETCHED_AT if value.get('source') == 'native' else None
                for source in value.get('sources', {}).values():
                    if isinstance(source, dict):
                        source['fetched_at'] = FETCHED_AT
        task['required_facts'] = leaves(task['steps'])
    return corpus


def run(corpus_path, encoding_name="o200k_base", help_file=None):
    import tiktoken
    raw = Path(corpus_path).read_bytes()
    corpus = json.loads(raw)
    if corpus["schema_version"] not in {1, 2, 3} or not corpus["tasks"]:
        raise ValueError("Unsupported corpus")
    if corpus["schema_version"] in {2, 3} and corpus != freeze(corpus["schema_version"]):
        raise ValueError("Current formatter fixture differs from frozen corpus")
    if not all(task["required_facts"] and task["split"] in {"train", "heldout"} for task in corpus["tasks"]):
        raise ValueError("Every task needs frozen required facts and a split")
    encoding = tiktoken.get_encoding(encoding_name)
    help_text = Path(help_file).read_text() if help_file is not None else cli_parser().format_help()
    results = {}
    for candidate in CANDIDATES:
        rows = [measure_task(task, candidate, encoding, help_text) for task in corpus["tasks"]]
        results[candidate] = {"tasks": rows, "totals": {
            split: {key: sum(row[key] for row in rows if row["split"] == split) for key in ("tokens", "bytes", "calls")}
            for split in ("train", "heldout")}}
    # No held-out values participate in selection. Tie-break favors unchanged compact JSON.
    eligible = ("compact_json", "table_2", "table_4", "table_8")
    winner = min(eligible, key=lambda c: results[c]["totals"]["train"]["tokens"])
    baseline = results["compact_json"]["totals"]
    chosen = results[winner]["totals"]
    accepted = chosen["heldout"]["tokens"] <= baseline["heldout"]["tokens"]
    return {"schema_version": corpus["schema_version"], "corpus_sha256": hashlib.sha256(raw).hexdigest(),
            "help_sha256": hashlib.sha256(help_text.encode()).hexdigest(),
            "tokenizer": {"package": "tiktoken", "version": version("tiktoken"), "encoding": encoding_name,
                          "claim": "proxy only; not GPT-6/GPT-6.1 tokens or billing"},
            "browser_baseline": "unavailable; no browser savings claim",
            "selected_on_training": winner,
            "retained": winner if accepted else "compact_json",
            "heldout_gate": "passed" if accepted else "rejected_token_regression",
            "savings_vs_compact_json": {split: {"tokens": baseline[split]["tokens"] - chosen[split]["tokens"],
                "percent": round(100 * (baseline[split]["tokens"] - chosen[split]["tokens"]) / baseline[split]["tokens"], 2)}
                for split in ("train", "heldout")},
            "candidates": results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="benchmarks/corpus-v3.json")
    parser.add_argument("--encoding", default="o200k_base")
    parser.add_argument("--help-file", help="Replay historical archived help, not current CLI discovery")
    parser.add_argument("--freeze", action="store_true", help="Freeze current metadata synthetic formatter study before scoring")
    args = parser.parse_args(argv)
    if args.freeze:
        if args.help_file:
            parser.error("Freeze cannot use historical help")
        Path(args.corpus).write_text(json.dumps(freeze(), indent=2) + "\n")
        return
    if args.help_file:
        print("Historical replay: archived discovery help and synthetic transcripts; not current CLI coverage evidence.", file=sys.stderr)
    print(json.dumps(run(args.corpus, args.encoding, args.help_file), indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
