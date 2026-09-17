"""Isolated API boundary smoke check; no live hosts, keys, or production DB."""
import gc
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sysadmin_mcp.audit import SQLiteAuditLog
from sysadmin_mcp.chat_store import SQLiteChatStore
from sysadmin_mcp.executor import ReadOnlyExecutor
from sysadmin_mcp.web import AgentService, create_app


def main():
    results = []
    with tempfile.TemporaryDirectory(prefix="api-review-") as directory:
        audit = SQLiteAuditLog(Path(directory) / "audit.db")
        executor = ReadOnlyExecutor({}, None, audit)
        service = AgentService({}, executor, model="test", client=SimpleNamespace(),
                               chat_store=SQLiteChatStore(audit.path))
        app = create_app(service, audit)
        with TestClient(app) as client:
            for route in app.routes:
                if not route.path.startswith("/api/") or route.path == "/api/auth/login":
                    continue
                path = route.path.replace("{transaction_id}", "missing").replace(
                    "{host_name}", "missing").replace(
                    "{session_id}", "00000000-0000-4000-8000-000000000000")
                for method in sorted(route.methods):
                    response = client.request(method, path)
                    results.append({"check": "unauthenticated", "method": method,
                                    "path": route.path, "status": response.status_code,
                                    "passed": response.status_code == 401})
            response = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
            assert response.status_code == 200
            csrf = {"x-csrf-token": response.json()["csrf_token"]}
            assert client.get("/api/hosts").status_code == 403
            assert client.post("/api/auth/change-password", headers=csrf,
                               json={"current_password": "admin", "new_password": "review-isolated-password"}).status_code == 200
            for route in app.routes:
                if route.path.startswith("/api/") and "GET" in route.methods and "{" not in route.path:
                    response = client.get(route.path)
                    results.append({"check": "authenticated empty-fleet GET", "method": "GET",
                                    "path": route.path, "status": response.status_code,
                                    "passed": response.status_code == 200})
            for route in app.routes:
                if route.path.startswith("/api/") and route.path != "/api/auth/login":
                    for method in sorted(route.methods - {"GET", "HEAD", "OPTIONS"}):
                        path = route.path.replace("{transaction_id}", "missing").replace(
                            "{session_id}", "00000000-0000-4000-8000-000000000000")
                        response = client.request(method, path, json={})
                        results.append({"check": "missing CSRF", "method": method,
                                        "path": route.path, "status": response.status_code,
                                        "passed": response.status_code == 403})
        # Store connection contexts commit but do not explicitly close handles.
        # Collect unreachable connections before Windows temporary-dir cleanup.
        gc.collect()
    output = Path(__file__).with_name("api-smoke.json")
    output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"{sum(row['passed'] for row in results)}/{len(results)} API boundary checks passed")
    for row in results:
        if not row["passed"]:
            print(row)
    return 0 if all(row["passed"] for row in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
