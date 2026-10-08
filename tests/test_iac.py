"""Infrastructure and workflow structure, checked offline (no Terraform or Bicep binaries needed)."""

import json
import re
from pathlib import Path

import pytest
import yaml

from idsec import iac

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github/workflows"
TF = ROOT / "infra/terraform"
BICEP = ROOT / "infra/bicep"
SHA_PIN = re.compile(r"uses:\s*[\w./-]+@[0-9a-f]{40}\b")
ROLE = iac.role_definition()


def tf_text() -> str:
    return "\n".join(p.read_text() for p in sorted(TF.glob("*.tf")))


def bicep_text() -> str:
    return "\n".join(p.read_text() for p in sorted(BICEP.rglob("*.bicep")))


# ---------------------------------------------------------------- the reader role
def test_role_actions_are_read_only():
    assert ROLE["actions"] and iac.non_read_actions(ROLE) == []
    assert not any("*" in a for a in ROLE["actions"] + ROLE["dataActions"]), "no wildcards"


def test_role_never_reads_secret_values():
    assert "Microsoft.KeyVault/vaults/secrets/readMetadata/action" in ROLE["dataActions"]
    assert not any("getSecret" in d or "keys/" in d or "certificates/" in d for d in ROLE["dataActions"])


def test_role_never_lists_keys_or_connection_secrets():
    banned = ("listKeys", "listSecrets", "listCredentials", "regenerateKey", "runCommand", "/write", "/delete", "/action")
    for a in ROLE["actions"]:
        assert not any(b in a for b in banned), a


def test_role_covers_what_the_collectors_read():
    from idsec.collectors import live

    for t in live.RESOURCE_TYPES:
        if t.endswith("/projects"):
            continue
        provider_type = "/".join(t.split("/")[:2])
        assert any(a.lower().startswith(provider_type) for a in ROLE["actions"]), t
    for need in ("roleAssignments/read", "roleEligibilityScheduleInstances/read", "federatedIdentityCredentials/read", "connections/read"):
        assert any(a.endswith(need) for a in ROLE["actions"]), need


def test_both_stacks_load_the_same_role_file():
    assert "../role/identity-posture-reader.json" in (TF / "locals.tf").read_text()
    assert "loadJsonContent('../role/identity-posture-reader.json')" in (BICEP / "main.bicep").read_text()


def test_no_built_in_privileged_roles_anywhere():
    text = tf_text() + bicep_text()
    for role in ('"Owner"', '"Contributor"', "'Owner'", "'Contributor'", "User Access Administrator", "Key Vault Secrets User"):
        assert role not in text, role
    assert "role_definition_name" not in tf_text(), "only the custom role is assigned"


def test_graph_permissions_are_read_only_and_match_the_collector_doc():
    from idsec.collectors import live

    perms = re.findall(r'"([A-Za-z]+\.Read[A-Za-z.]*)"', (TF / "locals.tf").read_text())
    assert len(perms) == 7 and all(".Read" in p for p in perms)
    for p in perms:
        assert p in live.__doc__, p


def test_graph_permissions_and_scan_job_are_opt_in():
    variables = (TF / "variables.tf").read_text()
    for var in ("grant_graph_permissions", "enable_scan_job", "private_networking"):
        assert re.search(rf'variable "{var}"[\s\S]*?default\s*=\s*false', variables), var
    main = (BICEP / "main.bicep").read_text()
    for p in ("enableScanJob", "privateNetworking"):
        assert f"param {p} bool = false" in main, p


# ---------------------------------------------------------------- identity and federation
def test_federated_subject_is_pinned_to_an_environment_in_both_stacks():
    assert re.search(r'subject\s+= "repo:\$\{var.github_repository\}:environment:\$\{var.environment\}"', (TF / "main.tf").read_text())
    assert "subject: 'repo:${githubRepository}:environment:${environment}'" in (BICEP / "modules/identity.bicep").read_text()
    for text in (tf_text(), bicep_text()):
        assert "pull_request" not in text and "refs/heads/*" not in text


def test_no_secrets_or_keys_in_infra():
    text = tf_text() + bicep_text()
    for word in ("client_secret", "clientSecret", "password", "azurerm_key_vault_secret", "listKeys", "primary_shared_key"):
        assert word not in text, word


def test_workspace_is_keyless_in_both_stacks():
    assert re.search(r"local_authentication_enabled\s*=\s*false", tf_text())
    assert "disableLocalAuth: true" in (BICEP / "modules/workspace.bicep").read_text()


def test_job_logs_use_diagnostic_settings_not_shared_keys():
    job = (TF / "job.tf").read_text()
    assert 'logs_destination               = "azure-monitor"' in job and "log_analytics_workspace_id     =" not in job
    b = (BICEP / "modules/job.bicep").read_text()
    assert "destination: 'azure-monitor'" in b and "sharedKey" not in b


def test_job_has_no_ingress_and_no_retries():
    assert "ingress {" not in (TF / "job.tf").read_text() and "ingress:" not in (BICEP / "modules/job.bicep").read_text()
    assert "replica_retry_limit          = 0" in (TF / "job.tf").read_text()
    assert "replicaRetryLimit: 0" in (BICEP / "modules/job.bicep").read_text()


def test_job_command_matches_in_both_stacks():
    tf = re.search(r'scan_command = trimspace\("(.+?) \$\{var.scan_collect_args\} (.+?)"\)', (TF / "locals.tf").read_text())
    b = (BICEP / "modules/job.bicep").read_text()
    assert tf and tf.group(1) in b and tf.group(2) in b


def test_private_network_has_delegated_subnet_and_nsg_in_both_stacks():
    t = (TF / "network.tf").read_text()
    assert "Microsoft.App/environments" in t and "azurerm_network_security_group" in t
    b = (BICEP / "modules/network.bicep").read_text()
    assert "Microsoft.App/environments" in b and "networkSecurityGroup" in b


def test_parity_of_resource_kinds():
    tf = " ".join(x for items in iac.terraform_resources().values() for x in items)
    bi = " ".join(x for items in iac.bicep_resources().values() for x in items)
    pairs = [
        ("azurerm_user_assigned_identity", "userAssignedIdentities"),
        ("azurerm_federated_identity_credential", "federatedIdentityCredentials"),
        ("azurerm_role_definition", "roleDefinitions"),
        ("azurerm_role_assignment", "roleAssignments"),
        ("azurerm_log_analytics_workspace", "Microsoft.OperationalInsights/workspaces"),
        ("azurerm_monitor_diagnostic_setting", "diagnosticSettings"),
        ("azurerm_container_app_environment", "managedEnvironments"),
        ("azurerm_container_app_job", "Microsoft.App/jobs"),
        ("azurerm_virtual_network", "virtualNetworks"),
        ("azurerm_network_security_group", "networkSecurityGroups"),
    ]
    for t, b in pairs:
        assert t in tf and b in bi, (t, b)


def test_prod_is_private_and_everything_else_stays_off():
    prod = (TF / "envs/prod.tfvars").read_text()
    assert re.search(r"private_networking\s*=\s*true", prod)
    assert re.search(r"enable_scan_job\s*=\s*false", prod) and re.search(r"grant_graph_permissions\s*=\s*false", prod)
    params = json.loads((BICEP / "main.parameters.json").read_text())["parameters"]
    assert params["enableScanJob"]["value"] is False


def test_checkov_has_no_skips():
    assert "skip-check" not in (ROOT / ".checkov.yaml").read_text()


def test_terraform_tests_cover_the_key_paths():
    t = (TF / "tests/plan.tftest.hcl").read_text()
    for run in (
        "dev_defaults",
        "github_federation_is_pinned_to_an_environment",
        "scan_job_private",
        "graph_permissions_are_read_only",
        "rejects_unknown_environment",
    ):
        assert f'run "{run}"' in t
    assert 'mock_provider "azurerm"' in t and 'mock_provider "azuread"' in t


# ---------------------------------------------------------------- workflows
@pytest.mark.parametrize("name", sorted(p.name for p in WF.glob("*.yml")))
def test_workflow_hardening(name):
    d = iac.workflow(name)
    assert d["permissions"] == {"contents": "read"}, "top-level permissions must be read-only"
    text = (WF / name).read_text()
    for line in text.splitlines():
        if "uses:" in line and not line.strip().startswith("#"):
            assert SHA_PIN.search(line), f"{name}: action not pinned to a commit SHA: {line.strip()}"
    assert "client-secret" not in text and "AZURE_CLIENT_SECRET" not in text
    assert "pull_request_target" not in text


def test_ci_runs_tests_gate_and_drift_checks():
    text = (WF / "ci.yml").read_text()
    for step in ("pytest -q", "idsec gate", "idsec synth --check", "render_docs.py --check", "gitleaks", "sbom-action", "bicep build", "ruff check"):
        assert step in text, step


def test_infra_runs_every_iac_gate():
    text = (WF / "infra.yml").read_text()
    for step in ("fmt -check", "validate", 'terraform -chdir="$STACK" test', "tflint", "checkov"):
        assert step in text, step


def test_deploy_is_gated_and_uses_oidc():
    jobs = iac.workflow("deploy.yml")["jobs"]
    for name in ("deploy-dev", "deploy-prod"):
        assert "vars.DEPLOY_ENABLED == 'true'" in jobs[name]["if"]
        assert jobs[name]["permissions"]["id-token"] == "write"
        assert any("azure/login" in s.get("uses", "") for s in jobs[name]["steps"])
    assert jobs["deploy-dev"]["environment"] == "dev" and jobs["deploy-prod"]["environment"] == "prod"
    assert "deploy-dev" in jobs["deploy-prod"]["needs"]
    assert "permissions" not in jobs["preflight"]


def test_teardown_needs_gate_and_confirmation():
    job = iac.workflow("teardown.yml")["jobs"]["teardown"]
    assert "vars.DEPLOY_ENABLED == 'true'" in job["if"] and "inputs.confirm == inputs.environment" in job["if"]


def test_codeql_scans_python_and_actions():
    text = (WF / "codeql.yml").read_text()
    assert "python" in text and "actions" in text and "security-events: write" in text


def test_dependabot_covers_every_ecosystem():
    d = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text())
    assert {u["package-ecosystem"] for u in d["updates"]} >= {"pip", "github-actions", "terraform"}


def test_deploy_script_subcommands_and_smoke_checks():
    text = (ROOT / ".github/scripts/deploy.sh").read_text()
    for fn in ("provision()", "smoke()", "destroy()"):
        assert fn in text
    assert "ends_with(@, '/read')" in text and "disableLocalAuth" in text
    assert "set -euo pipefail" in text


def test_bicep_destroy_removes_subscription_scoped_role():
    text = (ROOT / ".github/scripts/deploy.sh").read_text()
    assert "az role definition delete" in text and "az role assignment delete" in text


# ---------------------------------------------------------------- summaries
def test_iac_summaries():
    assert "non-read: 0" in " ".join(iac.PARTS["role"]())
    assert "can read secret values: False" in iac.PARTS["role"]()
    tf = iac.PARTS["terraform"]()
    assert any("azurerm_role_definition.reader" in x for x in tf) and any(x.startswith("plan tests (7)") for x in tf)
    assert any("module job -> modules/job.bicep" in x for x in iac.PARTS["bicep"]())
    wf_lines = iac.PARTS["workflows"]()
    assert sum("OIDC (id-token: write)" in x for x in wf_lines) == 3
    assert sum("gated by DEPLOY_ENABLED" in x for x in wf_lines) == 2
