import copy
import json
from pathlib import Path

import pytest
import tiktoken

from router_agent.benchmark import measure_task, run, validate
from router_agent.compact import pack, unpack

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks/corpus-v1.json"
ARCHIVED_HELP = CORPUS.parent / "help-v1-v2.txt"


def test_codec_preserves_unknown_false_gaps_reserved_objects_and_nested_rows():
    value = {"freshness": "unknown", "observed_at": None,
             "capability_gaps": ["unsupported"],
             "clients": [{"alias": "a", "online": None, "details": {"$table": ["literal"]}},
                         {"details": {"$object": "literal"}, "online": False, "alias": "b"}]}
    wire = pack(value)
    assert "$table" in wire["clients"]
    assert unpack(json.loads(json.dumps(wire))) == value


@pytest.mark.parametrize("payload", [
    {"$table": [["alias", "alias"], [["a", "b"]]]},
    {"$table": [["alias"], [["a", "b"]]]},
    {"$object": [["alias", "a"], ["alias", "b"]]},
])
def test_malformed_compact_output_rejected(payload):
    with pytest.raises(ValueError):
        unpack(payload)


def test_required_facts_reject_unknown_to_false_and_missing_gap():
    task = next(t for t in json.loads(CORPUS.read_text())["tasks"] if t["id"] == "vpn_state")
    damaged = copy.deepcopy(task["steps"])
    damaged[0]["stdout"]["data"]["vpn"] = False
    with pytest.raises(ValueError, match="Required fact lost"):
        validate(task, damaged)
    damaged = copy.deepcopy(task["steps"])
    damaged[0]["stdout"]["capability_gaps"] = []
    with pytest.raises((IndexError, ValueError)):
        validate(task, damaged)


def test_all_streams_followups_and_decoder_help_counted():
    corpus = json.loads(CORPUS.read_text())
    encoding = tiktoken.get_encoding("o200k_base")
    error = next(t for t in corpus["tasks"] if t["id"] == "heldout_timeout")
    measured = measure_task(error, "compact_json", encoding, "help\n")
    assert measured["component_tokens"]["stderr"] == len(encoding.encode(error["steps"][0]["stderr"])) > 0
    assert measured["tokens"] == sum(measured["component_tokens"].values())
    task = next(t for t in corpus["tasks"] if t["id"] == "specific_client")
    baseline = measure_task(task, "compact_json", encoding, "help\n")
    candidate = measure_task(task, "table_8", encoding, "help\n")
    assert baseline["calls"] == candidate["calls"] == 2
    assert candidate["component_tokens"]["help_instructions"] > baseline["component_tokens"]["help_instructions"]
    assert candidate["component_tokens"]["commands"] == baseline["component_tokens"]["commands"]


def test_hillclimb_is_reproducible_and_rejects_heldout_regression():
    first = run(CORPUS, help_file=ARCHIVED_HELP)
    assert first == run(CORPUS, help_file=ARCHIVED_HELP)
    assert first == json.loads((CORPUS.parent / "results-v1.json").read_text())
    assert first["selected_on_training"] == "table_8"
    assert first["retained"] == "compact_json"
    assert first["heldout_gate"] == "rejected_token_regression"
    assert first["savings_vs_compact_json"]["train"]["tokens"] > 0
    assert first["savings_vs_compact_json"]["heldout"]["tokens"] < 0
    assert all(row["valid"] for candidate in first["candidates"].values() for row in candidate["tasks"])
