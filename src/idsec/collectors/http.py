"""A read-only HTTP transport for the live collectors.

Only GET is allowed, plus POST to the Azure Resource Graph query endpoint (a read). Anything else
raises `ReadOnlyViolation` before a request leaves the process. Paging (`@odata.nextLink`,
`nextLink`, `$skipToken`) and throttling (429 with Retry-After, bounded) are handled here so each
collector stays a list of endpoints."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

ARG_URL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
ALLOWED_HOSTS = ("graph.microsoft.com", "management.azure.com")
ALLOWED_SUFFIXES = (".vault.azure.net", ".services.ai.azure.com")
Sender = Callable[[str, str, dict, bytes | None], tuple[int, dict, dict]]


class ReadOnlyViolation(RuntimeError):
    pass


def urllib_sender(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, dict, dict]:  # pragma: no cover - network
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"{}")


def check(method: str, url: str) -> None:
    u = urlparse(url)
    if u.scheme != "https":
        raise ReadOnlyViolation(f"refusing non-HTTPS URL {url}")
    host = u.hostname or ""
    if host not in ALLOWED_HOSTS and not host.endswith(ALLOWED_SUFFIXES):
        raise ReadOnlyViolation(f"host {host} is not an allowed read endpoint")
    if method == "GET":
        return
    if method == "POST" and url.split("?")[0] == ARG_URL:
        return
    raise ReadOnlyViolation(f"{method} {url} is not a read")


@dataclass
class Transport:
    token: Callable[[str], str]  # scope -> bearer token
    send: Sender = urllib_sender
    sleep: Callable[[float], None] = time.sleep
    max_retries: int = 4
    requests: list[tuple[str, str]] = field(default_factory=list)

    def request(self, method: str, url: str, scope: str, body: dict | None = None) -> dict:
        check(method, url)
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": f"Bearer {self.token(scope)}", "Accept": "application/json", "ConsistencyLevel": "eventual"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(self.max_retries + 1):
            self.requests.append((method, url))
            status, hdrs, payload = self.send(method, url, headers, data)
            if status == 429 and attempt < self.max_retries:
                self.sleep(min(float(hdrs.get("Retry-After", 2**attempt)), 60))
                continue
            if status >= 400:
                raise RuntimeError(f"{method} {url} -> {status}: {str(payload)[:200]}")
            return payload
        raise RuntimeError(f"{method} {url}: still throttled after {self.max_retries} retries")

    def get_all(self, url: str, scope: str) -> list[dict]:
        out: list[dict] = []
        while url:
            page = self.request("GET", url, scope)
            out += page.get("value", [])
            url = page.get("@odata.nextLink") or page.get("nextLink") or ""
        return out

    def resource_graph(self, query: str, subscriptions: list[str], scope: str = "https://management.azure.com/.default") -> list[dict]:
        rows: list[dict] = []
        skip = None
        while True:
            body = {"subscriptions": subscriptions, "query": query, "options": {"resultFormat": "objectArray", "$top": 1000}}
            if skip:
                body["options"]["$skipToken"] = skip
            page = self.request("POST", f"{ARG_URL}?api-version=2022-10-01", scope, body)
            rows += page.get("data", [])
            skip = page.get("$skipToken")
            if not skip:
                return rows
