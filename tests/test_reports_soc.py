"""Reports (HTML, markdown, CSV, executive summary) and the SOC alert export."""

import base64
import csv
import hashlib
import io
import json
import re

import pytest
from conftest import pid

from idsec import detections, remediation, report, soc
from idsec import graph as gmod


@pytest.fixture(scope="module")
def sim(base_inv, results):
    return remediation.simulate(base_inv, results)


def test_html_csp_hash_matches_the_inline_script(base_inv, g, results):
    h = report.to_html(base_inv, g, results)
    digest = base64.b64encode(hashlib.sha256(report.SCRIPT.encode()).digest()).decode()
    assert f"script-src 'sha256-{digest}'" in h and "default-src 'none'" in h
    assert h.count("<script>") == 1


def test_html_escapes_attacker_names(inv):
    inv.principals[pid(inv, "loan-docs-sync")].name = "<img src=x onerror=alert(1)>"
    g = gmod.build(inv)
    h = report.to_html(inv, g, detections.run(inv, g))
    assert "<img src=x" not in h and "&lt;img src=x onerror=alert(1)&gt;" in h


def test_html_lists_every_finding(base_inv, g, results, sim):
    h = report.to_html(base_inv, g, results, sim)
    assert len(re.findall(r"<tr data-sev=", h)) == 47 and "Simulated remediation" in h


@pytest.mark.parametrize("value,expected", [("=HYPERLINK(1)", "'=HYPERLINK(1)"), ("+1", "'+1"), ("-1", "'-1"), ("@x", "'@x"), ("ok", "ok"), (3, "3")])
def test_csv_formula_guard(value, expected):
    assert report.csv_cell(value) == expected


def test_csv_round_trip(results):
    rows = list(csv.DictReader(io.StringIO(report.to_csv(results))))
    assert len(rows) == 47 and {"id", "severity", "rule"} <= set(rows[0])


def test_md_cell_escapes_pipes_and_tags():
    assert report.md_cell("a|b<c>\nd") == "a\\|b&lt;c&gt; d"


def test_markdown_report(base_inv, g, results, sim):
    md = report.to_markdown(base_inv, g, results, sim)
    assert md.count("\n| ") >= 47 and "P05-01" in md


def test_executive_summary_uses_real_numbers(base_inv, g, results, sim):
    s = report.executive_summary(base_inv, g, results, sim)
    assert "35.8" in s and "90.5" in s and "47" in s


def test_write_all(tmp_path, base_inv, g, results, sim):
    names = {p.name for p in report.write_all(tmp_path, base_inv, g, results, sim)}
    assert names == {"report.html", "findings.md", "findings.csv", "executive-summary.md", "findings.json"}
    assert len(json.loads((tmp_path / "findings.json").read_text())) == 47


# ------------------------------------------------------------------------------------ SOC
@pytest.fixture(scope="module")
def rows(base_inv, results):
    return soc.export(base_inv, results)


def test_soc_rows_validate(rows):
    assert len(rows) == 47 and soc.validate(rows) == []


def test_soc_severity_mapping(rows):
    counts = {s: sum(r["AlertSeverity"] == s for r in rows) for s in ("High", "Medium", "Low")}
    assert counts == {"High": 10, "Medium": 20, "Low": 17}


def test_soc_ids_unique_and_tactics_known(rows):
    assert len({r["SystemAlertId"] for r in rows}) == 47
    for r in rows:
        assert set(r["Techniques"]) <= set(soc.TACTICS) or not r["Techniques"]


def test_soc_description_has_no_tenant_free_text(rows):
    blob = json.dumps(rows)
    assert "ignore prior instructions" not in blob.lower() and "SYSTEM NOTE" not in blob


def test_soc_validate_catches_problems(rows):
    bad = [dict(rows[0])]
    del bad[0]["Entities"]
    bad[0]["AlertSeverity"] = "Critical"
    assert len(soc.validate(bad)) >= 2


def test_rows_parse_like_the_soc_repo(rows):
    """Mirror of product_alerts() in Jagadish-azure-ai-soc (src/aisoc/detections.py)."""
    for row in json.loads(soc.dumps(rows)):
        ents = row["Entities"] if isinstance(row["Entities"], list) else json.loads(row["Entities"])
        values = [e.get("Name") or e.get("HostName") or e.get("Address") or e.get("Url") for e in ents]
        assert all(values) and all(e["Type"] for e in ents)
        assert row["AlertSeverity"] in ("High", "Medium", "Low", "Informational")
        assert isinstance(row["Techniques"], list) and isinstance(row["Tactics"], list) and isinstance(row["EventIds"], list)


def test_agent_entities_are_prefixed(rows):
    assert any(e["Name"].startswith("agent:") for r in rows for e in r["Entities"])
