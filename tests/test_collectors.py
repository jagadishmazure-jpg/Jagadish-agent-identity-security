"""Collectors: the read-only transport, the offline validator and a live-collector round trip
against a fake Microsoft Graph / ARM / Key Vault / Foundry built from the synthetic tenant."""

import copy
import json
import shutil
from urllib.parse import parse_qs, urlparse

import pytest

from idsec import TENANT_DATA, detections, inventory
from idsec import graph as gmod
from idsec.collectors import http, live, offline

GRAPH, ARM = live.GRAPH, live.ARM
SUBS = ["00000000-0000-0000-0000-0000000000a1", "00000000-0000-0000-0000-0000000000a2"]


# ------------------------------------------------------------------------------------ read-only check
@pytest.mark.parametrize(
    "method,url",
    [
        ("GET", f"{GRAPH}/users"),
        ("GET", f"{ARM}/subscriptions/x/providers/Microsoft.Authorization/roleAssignments"),
        ("GET", "https://kv-kr-prod-secrets.vault.azure.net/secrets?api-version=7.4"),
        ("GET", "https://aif.services.ai.azure.com/api/projects/p/assistants"),
        ("POST", f"{http.ARG_URL}?api-version=2022-10-01"),
    ],
)
def test_reads_are_allowed(method, url):
    http.check(method, url)


@pytest.mark.parametrize(
    "method,url",
    [
        ("POST", f"{GRAPH}/users"),
        ("PATCH", f"{GRAPH}/applications/x"),
        ("DELETE", f"{GRAPH}/servicePrincipals/x"),
        ("PUT", f"{ARM}/subscriptions/x/providers/Microsoft.Authorization/roleAssignments/y"),
        ("POST", f"{ARM}/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/runCommand"),
        ("POST", "https://kv.vault.azure.net/secrets/x/backup"),
        ("GET", "http://graph.microsoft.com/v1.0/users"),
        ("GET", "https://evil.example/graph"),
        ("GET", "https://graph.microsoft.com.evil.example/v1.0/users"),
        ("POST", f"{http.ARG_URL}/../../subscriptions"),
    ],
)
def test_writes_and_foreign_hosts_are_refused(method, url):
    with pytest.raises(http.ReadOnlyViolation):
        http.check(method, url)


def test_refused_request_never_reaches_the_sender():
    sent = []
    t = http.Transport(lambda s: "tok", send=lambda *a: sent.append(a) or (200, {}, {}))
    with pytest.raises(http.ReadOnlyViolation):
        t.request("DELETE", f"{GRAPH}/users/x", live.G)
    assert sent == []


# ------------------------------------------------------------------------------------ transport
def test_paging_follows_next_links():
    pages = {
        f"{GRAPH}/x": {"value": [1, 2], "@odata.nextLink": f"{GRAPH}/x?p=2"},
        f"{GRAPH}/x?p=2": {"value": [3], "nextLink": f"{GRAPH}/x?p=3"},
        f"{GRAPH}/x?p=3": {"value": []},
    }
    t = http.Transport(lambda s: "tok", send=lambda m, u, h, b: (200, {}, pages[u]))
    assert t.get_all(f"{GRAPH}/x", live.G) == [1, 2, 3] and len(t.requests) == 3


def test_throttling_retries_with_retry_after():
    replies = iter([(429, {"Retry-After": "7"}, {}), (429, {}, {}), (200, {}, {"value": ["ok"]})])
    slept = []
    t = http.Transport(lambda s: "tok", send=lambda *a: next(replies), sleep=slept.append)
    assert t.get_all(f"{GRAPH}/x", live.G) == ["ok"] and slept == [7.0, 2.0]


def test_retry_after_is_capped():
    replies = iter([(429, {"Retry-After": "3600"}, {}), (200, {}, {})])
    slept = []
    http.Transport(lambda s: "tok", send=lambda *a: next(replies), sleep=slept.append).request("GET", f"{GRAPH}/x", live.G)
    assert slept == [60]


def test_gives_up_after_max_retries():
    t = http.Transport(lambda s: "tok", send=lambda *a: (429, {}, {}), sleep=lambda s: None, max_retries=2)
    with pytest.raises(RuntimeError, match="throttled"):
        t.request("GET", f"{GRAPH}/x", live.G)
    assert len(t.requests) == 3


def test_http_errors_raise():
    t = http.Transport(lambda s: "tok", send=lambda *a: (403, {}, {"error": {"code": "Authorization_RequestDenied"}}))
    with pytest.raises(RuntimeError, match="403"):
        t.request("GET", f"{GRAPH}/x", live.G)


def test_headers_carry_token_for_the_right_scope():
    seen = {}

    def send(m, u, h, b):
        seen.update(h)
        return 200, {}, {}

    http.Transport(lambda scope: f"tok-for-{scope}", send=send).request("GET", f"{GRAPH}/x", live.G)
    assert seen["Authorization"] == f"Bearer tok-for-{live.G}" and seen["ConsistencyLevel"] == "eventual"


def test_resource_graph_pages_with_skip_token():
    bodies = []

    def send(m, u, h, b):
        body = json.loads(b)
        bodies.append(body)
        return (200, {}, {"data": [1], "$skipToken": "t2"}) if "$skipToken" not in body["options"] else (200, {}, {"data": [2]})

    assert http.Transport(lambda s: "tok", send=send).resource_graph("resources", SUBS) == [1, 2]
    assert bodies[1]["options"]["$skipToken"] == "t2" and bodies[0]["subscriptions"] == SUBS


# ------------------------------------------------------------------------------------ offline
def test_offline_validate_ok():
    assert offline.validate(TENANT_DATA) == []


def test_offline_validate_reports_missing_and_broken(tmp_path):
    shutil.copytree(TENANT_DATA, tmp_path / "t")
    (tmp_path / "t/graph/users.json").unlink()
    (tmp_path / "t/arm/resources.json").write_text("{nope")
    problems = offline.validate(tmp_path / "t")
    assert "missing graph/users.json" in problems and any("invalid JSON" in p for p in problems)


def test_offline_collect_copies(tmp_path):
    assert offline.collect(TENANT_DATA, tmp_path / "out") == []
    assert (tmp_path / "out/graph/users.json").exists()


def test_offline_collect_refuses_bad_input(tmp_path):
    (tmp_path / "src").mkdir()
    assert offline.collect(tmp_path / "src", tmp_path / "out")
    assert not (tmp_path / "out").exists()


# ------------------------------------------------------------------------------------ live round trip
def _load(rel):
    return json.loads((TENANT_DATA / rel).read_text())


def _select(obj, select, keep=()):
    fields = set(select.split(",")) | set(keep) | {"id"}
    return {k: v for k, v in obj.items() if k in fields}


class FakeCloud:
    """Answers the live collectors' requests from the synthetic files, the way the real APIs shape
    them: $select trims fields, members/owners/FICs/sponsors come from separate calls, lists page."""

    def __init__(self):
        self.calls = []
        self.throttled = False
        sps = copy.deepcopy(_load("graph/servicePrincipals.json")["value"])
        self.graph_sp = next(s for s in sps if s["displayName"] == "Microsoft Graph")
        self.assigned = [a for s in sps for a in s.get("appRoleAssignments", [])]
        self.agent_ids = [s["id"] for s in sps if s.get("@odata.type") == "#microsoft.graph.agentIdentity"]
        self.sponsors = {s["id"]: s.get("sponsors", []) for s in sps}
        for s in sps:
            if s is self.graph_sp:
                s["appId"] = live.MSGRAPH_APP_ID
        self.sps = [_select(s, live.SP_SELECT, keep=("owners",)) for s in sps]
        self.groups = _load("graph/groups.json")["value"]
        self.apps = _load("graph/applications.json")["value"]
        self.users = [_select(u, live.USER_SELECT) for u in _load("graph/users.json")["value"]]
        res = _load("arm/resources.json")["data"]
        self.resources = [r for r in res if not r["type"].endswith("/connections")]
        self.connections = [r for r in res if r["type"].endswith("/connections")]
        self.agents = _load("foundry/agents.json")["data"]

    def page(self, items, url, size=25):
        q = parse_qs(urlparse(url).query)
        start = int(q.get("skip", ["0"])[0])
        out = {"value": items[start : start + size]}
        if start + size < len(items):
            sep = "&" if "?" in url else "?"
            out["@odata.nextLink"] = url.split("&skip=")[0].split("?skip=")[0] + f"{sep}skip={start + size}"
        return out

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        if not self.throttled:
            self.throttled = True
            return 429, {"Retry-After": "1"}, {}
        path = urlparse(url).path
        if method == "POST":
            return 200, {}, self.arg(json.loads(body)["query"])
        if url.startswith(GRAPH):
            return 200, {}, self.graph(path.removeprefix("/v1.0"), url)
        if ".vault.azure.net" in url:
            vault = urlparse(url).hostname.split(".")[0]
            return 200, {}, _load(f"keyvault/{vault}.json")
        if ".services.ai.azure.com" in url:
            items = [{k: v for k, v in a.items() if k != "project"} for a in self.agents]
            after = parse_qs(urlparse(url).query).get("after", [None])[0]
            start = next(i for i, a in enumerate(items) if a["id"] == after) + 1 if after else 0
            chunk = items[start : start + 4]
            return 200, {}, {"object": "list", "data": chunk, "has_more": start + 4 < len(items), "last_id": chunk[-1]["id"]}
        return 200, {}, self.arm(path)

    def graph(self, path, url):
        simple = {
            "/reports/authenticationMethods/userRegistrationDetails": "userRegistrationDetails",
            "/oauth2PermissionGrants": "oauth2PermissionGrants",
            "/roleManagement/directory/roleDefinitions": "roleDefinitions",
            "/roleManagement/directory/roleAssignmentScheduleInstances": "roleAssignmentScheduleInstances",
            "/roleManagement/directory/roleEligibilitySchedules": "roleEligibilitySchedules",
            "/identity/conditionalAccess/policies": "conditionalAccessPolicies",
        }
        if path in simple:
            return {"value": _load(f"graph/{simple[path]}.json")["value"]}
        if path == "/users":
            return self.page(self.users, url)
        if path == "/groups":
            return {"value": [{k: v for k, v in g.items() if k != "members"} for g in self.groups]}
        if path.startswith("/groups/") and path.endswith("/members"):
            gid = path.split("/")[2]
            return {"value": [{"id": m["id"]} for m in next(g for g in self.groups if g["id"] == gid)["members"]]}
        if path == "/applications":
            return {"value": [{k: v for k, v in a.items() if k != "federatedIdentityCredentials"} for a in self.apps]}
        if path.endswith("/federatedIdentityCredentials"):
            aid = path.split("/")[2]
            return {"value": next(a for a in self.apps if a["id"] == aid).get("federatedIdentityCredentials", [])}
        if path == "/servicePrincipals":
            return self.page(self.sps, url, size=10)
        if path == "/servicePrincipals/microsoft.graph.agentIdentity":
            return {"value": [{"id": i} for i in self.agent_ids]}
        if path == f"/servicePrincipals/{self.graph_sp['id']}/appRoleAssignedTo":
            return {"value": self.assigned}
        if path.endswith("/microsoft.graph.agentIdentity/sponsors"):
            return {"value": [{"id": s["id"]} for s in self.sponsors[path.split("/")[2]]]}
        raise AssertionError(f"unexpected Graph call {path}")

    def arg(self, query):
        if query.startswith("resourcecontainers"):
            return {"data": _load("arm/resourceContainers.json")["data"]}
        if query.startswith("resources"):
            return {"data": self.resources}
        if "roledefinitions" in query:
            return {"data": _load("arm/roleDefinitions.json")["data"]}
        if "roleassignments" in query:
            return {"data": _load("arm/roleAssignments.json")["data"]}
        raise AssertionError(query)

    def arm(self, path):
        if path.endswith("/connections"):
            project = path.removesuffix("/connections")
            return {
                "value": [
                    {"id": c["id"], "name": c["name"], "properties": c["properties"]} for c in self.connections if c["id"].startswith(project + "/")
                ]
            }
        if path.endswith("/roleEligibilityScheduleInstances"):
            sub = path.split("/")[2]
            return {"value": [e for e in _load("arm/roleEligibilityScheduleInstances.json")["value"] if e["id"].startswith(f"/subscriptions/{sub}/")]}
        if path.endswith("/federatedIdentityCredentials"):
            return {"value": _load("arm/federatedIdentityCredentials.json").get(path.removesuffix("/federatedIdentityCredentials"), [])}
        raise AssertionError(f"unexpected ARM call {path}")


@pytest.fixture(scope="module")
def collected(tmp_path_factory, base_inv):
    out = tmp_path_factory.mktemp("live")
    cloud = FakeCloud()
    t = http.Transport(lambda s: "tok", send=cloud, sleep=lambda s: None)
    project = next(r for r in base_inv.resources.values() if r.name == "proj-lending-agents")
    vaults = [v.name for v in base_inv.vaults()]
    shutil.copytree(TENANT_DATA / "saas", out / "saas")  # SaaS admin exports are files, not API calls
    written = live.collect(out, SUBS, vaults, {project.id: "https://aif-kr-prod.services.ai.azure.com/api/projects/proj-lending-agents"}, t)
    return out, cloud, written


def test_live_collect_only_reads(collected):
    _, cloud, _ = collected
    assert all(m == "GET" or u.startswith(http.ARG_URL) for m, u in cloud.calls)
    assert not any("/secrets/" in u for _, u in cloud.calls), "secret values are never requested"


def test_live_collect_pages_and_retries(collected):
    _, cloud, _ = collected
    assert sum(u.startswith(f"{GRAPH}/users") for _, u in cloud.calls) > 2
    assert cloud.calls[0] == cloud.calls[1], "the throttled first call was retried"


def test_foundry_list_pages_with_after(collected):
    _, cloud, _ = collected
    assert any("after=" in u for _, u in cloud.calls)


def test_live_collect_writes_every_required_file(collected):
    out, _, written = collected
    assert offline.validate(out) == [] and len(written) >= 20


def test_live_round_trip_matches_offline_inventory(collected, base_inv):
    out, _, _ = collected
    inv = inventory.load(out)
    a, b = inventory.summary(inv), inventory.summary(base_inv)
    assert a == b


def test_live_round_trip_produces_the_same_findings(collected, found):
    out, _, _ = collected
    inv = inventory.load(out)
    g = gmod.build(inv)
    assert {(f.rule, f.subject) for r in detections.run(inv, g) for f in r.findings} == found


def test_live_module_documents_permissions():
    doc = live.__doc__
    for perm in ("User.Read.All", "Application.Read.All", "RoleManagement.Read.Directory", "Policy.Read.All", "AuditLog.Read.All"):
        assert perm in doc
    assert "ReadWrite" not in doc and "never run against a tenant" in doc
