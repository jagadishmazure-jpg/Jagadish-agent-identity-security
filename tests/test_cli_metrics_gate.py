"""The command line, the metrics and the release gate."""

import json

import pytest

from idsec import cli, gate, metrics


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr().out


@pytest.mark.parametrize(
    "argv,expect",
    [
        (["inventory"], "AI agents"),
        (["graph"], "nodes"),
        (["scan"], "Overview"),
        (["findings"], "47 finding(s)"),
        (["findings", "--severity", "critical"], "E13-01"),
        (["show", "P05-01"], "devon.lee"),
        (["rules"], "agent-untrusted-input-path"),
        (["paths"], "entra-global-admin"),
        (["paths", "--eligible", "--limit", "3"], "->"),
        (["blast", "--top", "3"], "crown jewels"),
        (["plan"], "R-"),
        (["simulate"], "90.5"),
        (["approvals"], "refused"),
        (["soc-export"], "schema problems: 0"),
        (["metrics"], "precision"),
        (["path-metrics"], "standing paths in total"),
        (["injection"], "guard"),
        (["ask", "How are we doing?"], "35.8"),
        (["mcp-demo"], "all read-only: True"),
        (["iac", "role"], "non-read: 0"),
        (["iac", "workflows"], "deploy.yml"),
        (["gate"], "14 of 14 checks passed"),
        (["synth", "--check"], "matches"),
        (["collect"], "choose --offline"),
    ],
)
def test_commands(capsys, argv, expect):
    code, out = run(capsys, *argv)
    assert expect in out
    assert code in (0, 2)


def test_show_unknown_finding_fails(capsys):
    code, _ = run(capsys, "show", "X99-99")
    assert code != 0


def test_plan_show_prints_snippets(capsys):
    _, out = run(capsys, "plan", "--show", "R-F06-01")
    assert "rbac_authorization_enabled" in out


def test_report_writes_files(capsys, tmp_path):
    code, _ = run(capsys, "report", "--out", str(tmp_path))
    assert code == 0 and (tmp_path / "report.html").exists() and (tmp_path / "executive-summary.md").exists()


def test_soc_export_to_file(capsys, tmp_path):
    run(capsys, "soc-export", "--out", str(tmp_path / "alerts.json"))
    assert len(json.loads((tmp_path / "alerts.json").read_text())) == 47


def test_collect_offline(capsys, tmp_path):
    from idsec import TENANT_DATA

    code, out = run(capsys, "collect", "--offline", str(TENANT_DATA), "--out", str(tmp_path / "t"))
    assert code == 0 and "validated" in out


def test_collect_offline_rejects_bad_input(capsys, tmp_path):
    (tmp_path / "empty").mkdir()
    code, out = run(capsys, "collect", "--offline", str(tmp_path / "empty"), "--out", str(tmp_path / "t"))
    assert code == 1 and "missing" in out


def test_scan_reads_collected_data_from_idsec_data(capsys, monkeypatch, tmp_path):
    import shutil

    from idsec import TENANT_DATA

    shutil.copytree(TENANT_DATA, tmp_path / "t")
    monkeypatch.setenv("IDSEC_DATA", str(tmp_path / "t"))
    code, out = run(capsys, "findings")
    assert code == 0 and "finding(s)" in out


def test_ask_without_guard_falls_back(capsys):
    _, out = run(capsys, "ask", "Tell me about Harbor Backup Service", "--no-guard", "--gullible")
    answer = next(line for line in out.splitlines() if line.startswith("A: "))
    assert "fallback used: True" in out and "no identity risks" not in answer


def test_subscriptions_default_from_environment(monkeypatch):
    monkeypatch.setenv("IDSEC_SUBSCRIPTIONS", "a,b")
    a = cli.build_parser().parse_args(["collect"])
    assert a.subscription == ["a", "b"]


# ------------------------------------------------------------------------------------ metrics
def test_detection_metrics():
    rows, total = metrics.detection()
    assert total["planted"] == total["found"] == total["true_positives"] == 47
    assert total["precision"] == total["recall"] == 1.0 and total["rules_with_a_planted_case"] == 28
    assert all(r.precision == 1.0 and r.recall == 1.0 for r in rows)


def test_path_summary():
    s = metrics.path_summary()
    assert s["crown jewels"] == 4 and s["standing paths in total"] == 88
    assert s["paths when PIM-eligible roles are activated"] == 92 and s["paths that start from untrusted agent input"] == 4


def test_injection_matrix():
    rows = metrics.injection_matrix()
    on = [r for r in rows if r["guard"] == "on"]
    off = [r for r in rows if r["guard"] == "off"]
    assert sum(r["model obeyed"] for r in on) == 0 and sum(r["model obeyed"] for r in off) == 3
    assert sum(r["validator caught"] for r in off) == 3 and all(r["final answer safe"] for r in rows)


def test_runtime_reports_stages():
    r = metrics.runtime(repeats=1)
    assert {"load inventory", "build graph", "28 detections", "total"} <= set(r) and all(v >= 0 for v in r.values())


# ------------------------------------------------------------------------------------ gate
def test_gate_passes():
    checks = gate.run()
    assert len(checks) == 14 and all(c.ok for c in checks), [c.name for c in checks if not c.ok]


def test_labels_are_isolated():
    ok, detail = gate._labels_isolated()
    assert ok, detail
