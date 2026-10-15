import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from router_agent import cli
from router_agent.benchmark import validate
from router_agent.benchmark_clients import capture
from router_agent.benchmark_diff import execute_case, freeze_actual, run, run_actual
from router_agent.compact import unpack
from router_agent.snapshots import SnapshotStore

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks/corpus-diff-v6.json"


def test_all_changes_task_uses_real_store_and_counts_followup_pages():
    task = execute_case({"id": "all_changes", "split": "train", "kind": "clients", "count": 35})
    assert len(task["steps"]) == 2
    assert [len(step["stdout"]["data"]["changes"]) for step in task["steps"]] == [20, 15]
    assert [step["stdout"]["data"]["pagination"]["next_offset"] for step in task["steps"]] == [20, None]
    assert all(step["stdout"]["data"]["total_changes"] == 35 for step in task["steps"])
    assert all(step["stdout"]["freshness"] == "not_collected" and step["stdout"]["observed_at"] is None for step in task["steps"])


def test_presence_null_and_array_changes_are_distinct():
    task = execute_case({"id": "presence", "split": "heldout", "kind": "presence", "count": 5})
    changes = task["expected_changes"]
    removed = next(change for change in changes if change["path"] == "/config/enabled")
    added = next(change for change in changes if change["path"] == "/config/hostname")
    assert removed["before"] is removed["after"] is added["before"] is added["after"] is None
    assert removed["before_present"] is True and removed["after_present"] is False
    assert added["before_present"] is False and added["after_present"] is True
    assert {change["path"] for change in changes if "/sources/" in change["path"]} == {"/config/sources/0", "/config/sources/1"}
    damaged = copy.deepcopy(task["steps"])
    damaged[0]["stdout"]["data"]["changes"][1]["after_present"] = True
    with pytest.raises(ValueError, match="Required fact lost"):
        validate(task, damaged)


def test_actual_cli_benchmark_preserves_facts_and_charges_help_flag_overhead(tmp_path):
    path = tmp_path / "current.json"
    corpus = freeze_actual()
    path.write_text(json.dumps(corpus))
    result = run_actual(path)
    assert result["heldout_gate"] == "passed"
    assert result["runtime_default"] == "compact_json"
    assert result["savings_vs_compact_json"]["train"]["tokens"] > 0
    assert result["savings_vs_compact_json"]["heldout"]["tokens"] > 0
    selected = result["candidates"][result["selected_on_training"]]["tasks"]
    assert [row["calls"] for row in selected] == [2, 2, 1]
    assert all(row["valid"] and row["discovery_calls"] == 2 for row in selected)
    assert all(row["component_tokens"]["help_instructions"] == 0 for row in selected)
    assert "$table" in corpus["discovery"][1]["stdout"]
    baseline = result["candidates"]["compact_json"]["tasks"]
    assert selected[2]["tokens"] > baseline[2]["tokens"]
    assert selected[0]["component_tokens"]["commands"] > baseline[0]["component_tokens"]["commands"]
    for task in corpus["tasks"]:
        for normal, encoded in zip(task["steps"], task["table_steps"], strict=True):
            assert json.dumps(unpack(encoded["stdout"]), sort_keys=True) == json.dumps(normal["stdout"], sort_keys=True)
    assert all(row["tokens"] == sum(row["component_tokens"].values()) for row in selected)


@pytest.mark.parametrize("output_format", ["json", "table"])
def test_real_cli_refuses_incompatible_snapshot_identity(tmp_path, output_format):
    store = SnapshotStore(tmp_path)
    identity = {"schema": 1, "device": "synthetic-a", "firmware": "synthetic", "catalog": "synthetic"}
    old = store.save({"config": {"enabled": None}}, identity, kind="config")
    new = store.save({"config": {"enabled": True}}, dict(identity, device="synthetic-b"), kind="config")
    with patch.object(cli, "SnapshotStore", lambda: store):
        response = capture(["diff", "--since", old["snapshot_id"], "--to", new["snapshot_id"], "--format", output_format])
    assert response["exit_code"] != 0
    payload = json.loads(response["stdout"])
    assert payload["error"]["code"] == "baseline_reset"
    assert "data" not in payload


def test_explicit_archival_replay_survives_current_help_drift_without_relabeling():
    changed = freeze_actual()
    changed["discovery"][0]["stdout"] += "Changed current help\n"
    with patch("router_agent.benchmark_diff.freeze_actual", return_value=changed):
        with pytest.raises(ValueError, match="differs from frozen"):
            run_actual(CORPUS)
        archived = run(CORPUS.parent / "corpus-diff-v1.json", historical_format_study=True)
    assert archived == json.loads((CORPUS.parent / "results-diff-v1.json").read_text())
    assert archived["candidate_status"].startswith("experimental pure formatter")


def test_archival_replay_rejects_omitted_followup_page(tmp_path):
    corpus = json.loads((CORPUS.parent / "corpus-diff-v1.json").read_text())
    corpus["tasks"][0]["steps"].pop()
    path = tmp_path / "damaged-archive.json"
    path.write_text(json.dumps(corpus))
    with pytest.raises(ValueError, match="preserve every expected change"):
        run(path, historical_format_study=True)

@pytest.mark.parametrize('archive_version', [2, 3])
def test_historical_actual_cli_help_preserves_archive_but_rejects_fact_drift(tmp_path, archive_version):
    archived=CORPUS.parent/f'corpus-diff-v{archive_version}.json'
    with pytest.raises(ValueError,match='differs from frozen'):run_actual(archived)
    assert run_actual(archived,historical_help=True,historical_schema=True)==json.loads((CORPUS.parent/f'results-diff-v{archive_version}.json').read_text())
    corrupted=json.loads(archived.read_text())
    corrupted['tasks'][0]['steps'][0]['stdout']['data']['changes'][0]['after']='changed'
    path=tmp_path/'corrupted.json';path.write_text(json.dumps(corrupted))
    with pytest.raises(ValueError,match='differs from frozen'):run_actual(path,historical_help=True,historical_schema=True)


def test_historical_help_requires_explicit_archive_and_cannot_freeze():
    from router_agent.benchmark_diff import main
    for args in (['--historical-help'],['--historical-help','--corpus',str(CORPUS),'--freeze'],['--historical-help','--historical-format-study','--corpus',str(CORPUS)]):
        with pytest.raises(SystemExit) as error:main(args)
        assert error.value.code==2
