"""The doc renderer: output blocks and code excerpts."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_docs", ROOT / "scripts/render_docs.py")
rd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rd)


def test_output_block_is_filled_from_the_cli():
    out = rd.render("<!-- output: findings --severity critical -->\nstale\n<!-- /output -->\n")
    assert "E13-01" in out and "stale" not in out


def test_python_excerpt_is_the_current_function():
    lang, body = rd.excerpt("src/idsec/remediation.py::approve")
    assert lang == "python" and body.startswith("def approve")


def test_constant_excerpt():
    _, body = rd.excerpt("src/idsec/guardrails.py::PATTERNS")
    assert body.startswith("PATTERNS")


def test_hcl_block_excerpt_balances_braces():
    lang, body = rd.excerpt('infra/terraform/main.tf::resource "azurerm_role_definition" "reader"')
    assert lang == "hcl" and body.count("{") == body.count("}")


def test_bicep_block_excerpt():
    lang, body = rd.excerpt("infra/bicep/modules/identity.bicep::resource github")
    assert lang == "bicep" and body.rstrip().endswith("}")


def test_whole_file_excerpt():
    lang, body = rd.excerpt("infra/role/identity-posture-reader.json")
    assert lang == "json" and "readMetadata" in body


def test_unknown_name_fails():
    with pytest.raises(SystemExit):
        rd.excerpt("src/idsec/scoring.py::nope")


def test_failing_command_fails_the_render():
    with pytest.raises(SystemExit):
        rd.run("show X99-99")
