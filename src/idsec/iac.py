"""Summaries of the infrastructure code, read from the files themselves (`idsec iac PART`).

They feed the docs (rendered by scripts/render_docs.py, so they cannot drift) and the IaC tests:
what the reader role allows, which resources each Terraform and Bicep file declares, and how each
workflow is triggered, permissioned and gated."""

from __future__ import annotations

import json
import re

import yaml

from idsec import ROOT

TF = ROOT / "infra/terraform"
BICEP = ROOT / "infra/bicep"
WORKFLOWS = ROOT / ".github/workflows"
ROLE = ROOT / "infra/role/identity-posture-reader.json"


def role_definition() -> dict:
    return json.loads(ROLE.read_text())


def non_read_actions(role: dict) -> list[str]:
    return [a for a in role["actions"] if not a.endswith("/read")]


def role() -> list[str]:
    r = role_definition()
    out = [f"role: {r['roleName']}", f"actions: {len(r['actions'])} (non-read: {len(non_read_actions(r))})"]
    providers: dict[str, int] = {}
    for a in r["actions"]:
        providers[a.split("/")[0]] = providers.get(a.split("/")[0], 0) + 1
    out += [f"  {p}: {n}" for p, n in sorted(providers.items())]
    out.append(f"data actions: {len(r['dataActions'])}")
    out += [f"  {d}" for d in r["dataActions"]]
    out.append(f"can read secret values: {any('getSecret' in d or d.endswith('secrets/*') for d in r['dataActions'])}")
    return out


def terraform_resources() -> dict[str, list[str]]:
    out = {}
    for p in sorted(TF.glob("*.tf")):
        found = re.findall(r'^(resource|data) "([a-z0-9_]+)" "([a-z0-9_]+)"', p.read_text(), re.M)
        if found:
            out[p.name] = [f"{'data.' if k == 'data' else ''}{t}.{n}" for k, t, n in found]
    return out


def terraform() -> list[str]:
    out = []
    for f, items in terraform_resources().items():
        out.append(f"{f}:")
        out += [f"  {x}" for x in items]
    tests = re.findall(r'^run "([a-z0-9_]+)"', (TF / "tests/plan.tftest.hcl").read_text(), re.M)
    out.append(f"plan tests ({len(tests)}): {', '.join(tests)}")
    return out


def bicep_resources() -> dict[str, list[str]]:
    out = {}
    for p in [BICEP / "main.bicep", *sorted((BICEP / "modules").glob("*.bicep"))]:
        text = p.read_text()
        items = [
            f"{n} ({t.split('@')[0]}{', existing' if ex else ''})" for n, t, ex in re.findall(r"^resource (\w+) '([^']+)'( existing)?", text, re.M)
        ]
        items += [f"module {n} -> {m}" for n, m in re.findall(r"^module (\w+) '([^']+)'", text, re.M)]
        out[str(p.relative_to(BICEP))] = items
    return out


def bicep() -> list[str]:
    out = []
    for f, items in bicep_resources().items():
        out.append(f"{f}:")
        out += [f"  {x}" for x in items]
    return out


def workflow(name: str) -> dict:
    doc = yaml.safe_load((WORKFLOWS / name).read_text())
    doc["on"] = doc.pop(True, doc.get("on"))  # YAML 1.1 reads the key `on` as true
    return doc


def workflows() -> list[str]:
    out = []
    for p in sorted(WORKFLOWS.glob("*.yml")):
        w = workflow(p.name)
        on = w["on"]
        triggers = ", ".join(on if isinstance(on, list) else on.keys())
        oidc = [j for j, d in w["jobs"].items() if (d.get("permissions") or {}).get("id-token") == "write"]
        gated = [j for j, d in w["jobs"].items() if "DEPLOY_ENABLED" in str(d.get("if", ""))]
        out.append(f"{p.name}: on {triggers}; default permissions {w['permissions']}")
        out.append(f"  jobs: {', '.join(w['jobs'])}")
        if oidc:
            out.append(f"  OIDC (id-token: write): {', '.join(oidc)}")
        if gated:
            out.append(f"  gated by DEPLOY_ENABLED: {', '.join(gated)}")
    return out


PARTS = {"role": role, "terraform": terraform, "bicep": bicep, "workflows": workflows}
