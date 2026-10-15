import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from router_agent.benchmark_clients import capture, freeze, run, validate_answer

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks/corpus-v7-clients.json"


def test_current_transcripts_match_actual_cli_and_heldout_passes(tmp_path):
    current = tmp_path / "current.json"
    current.write_text(json.dumps(freeze(schema_version=7)))
    result = run(current)
    assert result["selected_on_training"] == "exact_alias"
    assert result["heldout_gate"] == "passed"
    assert all(row["required_answer_valid"] and row["saved_tokens"] > 0 for row in result["tasks"])
    train, heldout = result["tasks"]
    assert train["candidates"]["paginated_search"]["response_calls"] == 2
    assert heldout["candidates"]["paginated_search"]["response_calls"] == 4
    assert all(row["candidates"]["exact_alias"]["response_calls"] == 1 for row in result["tasks"])
    assert all(score["discovery_calls"] == 2 for row in result["tasks"] for score in row["candidates"].values())


@pytest.mark.parametrize("damage", ["unknown_to_false", "hide_gap", "wrong_match_count"])
def test_required_answer_preserves_unknown_gaps_and_match_count(damage):
    task = json.loads(CORPUS.read_text())["tasks"][0]
    steps = copy.deepcopy(task["transcripts"]["exact_alias"])
    data = json.loads(steps[0]["stdout"])
    if damage == "unknown_to_false":
        data["data"]["clients"][0]["online"] = False
    elif damage == "hide_gap":
        data["capability_gaps"] = []
    else:
        data["pagination"]["total"] = 0
    steps[0]["stdout"] = json.dumps(data)
    with pytest.raises(ValueError):
        validate_answer(task, "exact_alias", steps)


def test_empty_or_partial_baseline_cannot_claim_requested_client():
    task = json.loads(CORPUS.read_text())["tasks"][0]
    with pytest.raises(ValueError, match="Required answer lost"):
        validate_answer(task, "paginated_search", task["transcripts"]["paginated_search"][:1])


def test_archived_corpus_drift_fails_closed(tmp_path):
    corpus = json.loads(CORPUS.read_text())
    corpus["tasks"][0]["transcripts"]["exact_alias"][0]["stderr"] = "omitted notice"
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match="differs from frozen"):
        run(path, historical_help=True)


@pytest.mark.parametrize("archive_version",[2,3,4])
def test_historical_help_reproduces_archive_without_claiming_current_discovery(archive_version):
    path = CORPUS.parent / f"corpus-v{archive_version}-clients.json"
    result = run(path, historical_help=True,historical_schema=True)
    assert result == json.loads((CORPUS.parent / f"results-v{archive_version}-clients.json").read_text())


def test_historical_mode_accepts_discovery_drift_but_current_mode_rejects_it():
    def changed_help(argv, source=None):
        value = capture(argv, source)
        if "--help" in argv:
            value["stdout"] += "New current help instructions\n"
        return value
    with patch("router_agent.benchmark_clients.capture", changed_help):
        with pytest.raises(ValueError, match="differs from frozen"):
            run(CORPUS)
        assert run(CORPUS, historical_help=True)["heldout_gate"] == "passed"
