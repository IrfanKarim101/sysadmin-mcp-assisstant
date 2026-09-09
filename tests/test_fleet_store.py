from pathlib import Path

from sysadmin_mcp.fleet_store import FleetSnapshotStore


def test_history_is_persistent_host_scoped_and_bounded(tmp_path: Path):
    path = tmp_path / "fleet.db"
    store = FleetSnapshotStore(path)
    store.append_many([
        {"name": "vm-a", "status": "healthy", "cpu_percent": 10.0,
         "memory_percent": 20.0, "disk_percent": 30.0, "message": "ok"},
        {"name": "vm-b", "status": "offline", "cpu_percent": None,
         "memory_percent": None, "disk_percent": None, "message": "offline"},
    ])
    assert len(FleetSnapshotStore(path).history("vm-a", 10_000)) == 1
    assert store.history("vm-a")[0]["cpu_percent"] == 10.0
    assert store.history("vm-a; DROP TABLE fleet_snapshots") == []
