import pytest
from router_agent.catalog import Catalog, load_catalog


def test_inventory_is_not_functionality():
    data = load_catalog().manifest()
    assert len(data["pages"]) == 69
    assert all(page["status"] == "inventory_only" for page in data["pages"])
    assert all(page["gaps"] for page in data["pages"])
    assert all(action["status"] == "inventory_only" for page in data["pages"] for action in page["actions"])
    assert data["operations"][0]["source"].startswith("SYNTHETIC")
    assert data["operations"][0]["offline_only"]


def test_catalog_rejects_unknown_keys():
    for target in ("top", "page", "operation", "field"):
        data = load_catalog().manifest()
        value = {"top": data, "page": data["pages"][0], "operation": data["operations"][0], "field": data["operations"][0]["fields"]["enabled"]}[target]
        value["rc_service"] = "reboot"
        with pytest.raises(ValueError, match="structure"):
            Catalog(data)


def test_catalog_immutable_and_unknown_operation():
    catalog = load_catalog()
    original = catalog.hash
    catalog.manifest()["pages"].clear()
    assert catalog.hash == original
    assert catalog.manifest()["pages"]
    with pytest.raises(ValueError, match="unsupported_operation"):
        catalog.operation("nvram")
