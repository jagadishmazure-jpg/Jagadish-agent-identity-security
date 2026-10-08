"""Findings explorer outputs: a self-contained static HTML report, a markdown report and CSV for
auditors, and a one-page executive summary.

Tenant text (names, evidence that embeds names) is attacker-controlled, so: HTML output escapes
every value and ships a Content-Security-Policy that allows only the report's own inline script (by
hash); CSV cells that a spreadsheet would treat as a formula are prefixed with an apostrophe;
markdown output escapes table pipes and angle brackets."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from pathlib import Path

from idsec import detections, paths, scoring
from idsec.guardrails import html as esc
from idsec.inventory import Inventory, summary

FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

SCRIPT = """
const rows=[...document.querySelectorAll('#findings tbody tr')];
function apply(){const s=document.getElementById('sev').value,a=document.getElementById('area').value,q=document.getElementById('q').value.toLowerCase();
let n=0;for(const r of rows){const ok=(!s||r.dataset.sev===s)&&(!a||r.dataset.area===a)&&(!q||r.textContent.toLowerCase().includes(q));r.hidden=!ok;n+=ok;}
document.getElementById('count').textContent=n+' shown';}
for(const id of ['sev','area','q'])document.getElementById(id).addEventListener('input',apply);apply();
""".strip()


def csv_cell(value: object) -> str:
    s = str(value)
    return "'" + s if s.startswith(FORMULA_START) else s


def md_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _rows(results):
    for f in detections.all_findings(results):
        m = f.meta
        yield {
            "id": f.id, "severity": f.severity, "area": f.area, "rule": f.rule, "title": f.title, "subject": f.label,
            "evidence": " | ".join(f.evidence), "attack": " ".join(m.get("attack", [])), "atlas": " ".join(m.get("atlas", [])),
            "owasp_llm": " ".join(m.get("owasp_llm", [])), "cis": " ".join(m.get("cis", [])), "zero_trust": m.get("zero_trust", ""), "fix": m["fix"],
        }  # fmt: skip


def to_csv(results) -> str:
    buf = io.StringIO()
    rows = list(_rows(results))
    w = csv.DictWriter(buf, fieldnames=list(rows[0]) if rows else ["id"], lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: csv_cell(v) for k, v in r.items()})
    return buf.getvalue()


def executive_summary(inv: Inventory, g, results, sim=None) -> str:
    sc = scoring.score(results)
    fs = detections.all_findings(results)
    by_sev = {s: sum(f.severity == s for f in fs) for s in ("critical", "high", "medium", "low")}
    ps = paths.analyse(inv, g)
    people = {p.source for p in ps if g.nodes[p.source]["kind"] in ("user", "guest")}
    lines = [
        f"# Identity security posture: {inv.tenant_name}",
        "",
        "Synthetic tenant, offline scan. Scores run from 0 to 100; see docs/components/scoring.md for the method.",
        "",
        "| Area | Score | Grade | Open findings |",
        "|---|---|---|---|",
        *[f"| {scoring.AREA_LABELS.get(k, 'Overview')} | {v.score} | {scoring.grade(v.score)} | {v.findings} |" for k, v in sc.items()],
        "",
        f"**Findings by severity:** {by_sev['critical']} critical, {by_sev['high']} high, {by_sev['medium']} medium, {by_sev['low']} low.",
        "",
        f"**Paths to crown jewels:** {len(ps)} standing paths from {len({p.source for p in ps})} identities, agents or outside sources; "
        f"{len(people)} people can reach a crown jewel today.",
        "",
        "## Fix first",
        "",
        *[
            f"{i}. **{md_cell(f.id)}** {md_cell(f.title)}: {md_cell(f.label)}"
            for i, f in enumerate([f for f in fs if f.severity == "critical"][:6], 1)
        ],
    ]
    if sim is not None:
        lines += [
            "",
            "## If the remediation plan is approved (simulation)",
            "",
            f"Overview {sim.before['overview'].score} to {sim.after['overview'].score}; open findings {sim.before['overview'].findings} to "
            f"{sim.after['overview'].findings}; standing paths from people and outside sources {sim.paths_before} to {sim.paths_after}. "
            f"{len(sim.skipped)} items need a person to act or are re-checked after the others.",
        ]
    return "\n".join(lines) + "\n"


def to_markdown(inv: Inventory, g, results, sim=None) -> str:
    out = [executive_summary(inv, g, results, sim), "## All findings", "", "| ID | Severity | Area | Title | Subject |", "|---|---|---|---|---|"]
    for r in _rows(results):
        out.append(f"| {r['id']} | {r['severity']} | {r['area']} | {md_cell(r['title'])} | {md_cell(r['subject'])} |")
    out += ["", "## Evidence and mappings", ""]
    for r in _rows(results):
        out += [
            f"### {r['id']} {md_cell(r['title'])}",
            "",
            f"- Subject: {md_cell(r['subject'])}",
            f"- Evidence: {md_cell(r['evidence'])}",
            f"- ATT&CK: {r['attack'] or '-'}; ATLAS: {r['atlas'] or '-'}; OWASP LLM: {r['owasp_llm'] or '-'}; CIS: {r['cis'] or '-'}; Zero Trust: {r['zero_trust']}",
            f"- Fix: {md_cell(r['fix'])}",
            "",
        ]
    return "\n".join(out)


def to_html(inv: Inventory, g, results, sim=None) -> str:
    sc = scoring.score(results)
    digest = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{digest}'; img-src 'none'; base-uri 'none'; form-action 'none'"
    cards = "".join(
        f"<div class='card'><div class='k'>{esc(scoring.AREA_LABELS.get(k, 'Overview'))}</div><div class='v'>{v.score}</div>"
        f"<div class='k'>grade {scoring.grade(v.score)}, {v.findings} findings</div></div>"
        for k, v in sc.items()
    )
    inv_rows = "".join(f"<tr><td>{esc(k)}</td><td>{v}</td></tr>" for k, v in summary(inv).items())
    rows = []
    for f in detections.all_findings(results):
        m = f.meta
        maps = " ".join(m.get("attack", []) + m.get("atlas", []) + m.get("owasp_llm", []))
        rows.append(
            f"<tr data-sev='{esc(f.severity)}' data-area='{esc(f.area)}'><td>{esc(f.id)}</td><td class='{esc(f.severity)}'>{esc(f.severity)}</td>"
            f"<td>{esc(f.area)}</td><td>{esc(f.title)}</td><td>{esc(f.label)}</td><td><details><summary>{len(f.evidence)} line(s)</summary><ul>"
            + "".join(f"<li>{esc(e)}</li>" for e in f.evidence)
            + f"</ul></details></td><td>{esc(maps)}</td><td>{esc(m['fix'])}</td></tr>"
        )
    ps = paths.analyse(inv, g)[:12]
    path_rows = "".join(f"<tr><td>{esc(p.jewel)}</td><td>{p.hops}</td><td>{p.risk}</td><td>{esc(p.render(g))}</td></tr>" for p in ps)
    sim_html = ""
    if sim is not None:
        sim_html = (
            "<h2>Simulated remediation (what-if, nothing applied)</h2><table><tr><th>Area</th><th>Before</th><th>After</th></tr>"
            + "".join(f"<tr><td>{esc(k)}</td><td>{sim.before[k].score}</td><td>{sim.after[k].score}</td></tr>" for k in sim.before)
            + "</table>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Identity security posture: {esc(inv.tenant_name)}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1b1f24}} table{{border-collapse:collapse;width:100%;margin:1rem 0}}
td,th{{border:1px solid #d0d7de;padding:.35rem .5rem;vertical-align:top;font-size:.9rem}} th{{background:#f6f8fa;text-align:left}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}} .card{{border:1px solid #d0d7de;border-radius:8px;padding:1rem;min-width:12rem}}
.v{{font-size:2rem;font-weight:600}} .k{{color:#57606a;font-size:.85rem}} .critical{{color:#a40e26;font-weight:600}} .high{{color:#bc4c00}}
.controls{{display:flex;gap:.5rem;align-items:center}}
</style></head><body>
<h1>Identity security posture: {esc(inv.tenant_name)}</h1>
<p>Synthetic data, offline scan. Every value below is escaped; tenant text is untrusted.</p>
<div class="cards">{cards}</div>
<h2>Inventory</h2><table>{inv_rows}</table>
<h2>Findings explorer</h2>
<div class="controls"><label>Severity <select id="sev"><option value="">all</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label>
<label>Area <select id="area"><option value="">all</option><option>privilege</option><option>foundational</option><option>emerging</option></select></label>
<label>Search <input id="q" type="search"></label><span id="count"></span></div>
<table id="findings"><thead><tr><th>ID</th><th>Severity</th><th>Area</th><th>Title</th><th>Subject</th><th>Evidence</th><th>Mappings</th><th>Fix</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table>
<h2>Riskiest paths to crown jewels</h2><table><tr><th>Crown jewel</th><th>Hops</th><th>Ease</th><th>Path</th></tr>{path_rows}</table>
{sim_html}
<script>{SCRIPT}</script>
</body></html>
"""


def write_all(out: Path, inv: Inventory, g, results, sim=None) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "report.html": to_html(inv, g, results, sim),
        "findings.md": to_markdown(inv, g, results, sim),
        "findings.csv": to_csv(results),
        "executive-summary.md": executive_summary(inv, g, results, sim),
        "findings.json": json.dumps([dict(r) for r in _rows(results)], indent=1),
    }
    written = []
    for name, text in files.items():
        (out / name).write_text(text)
        written.append(out / name)
    return written
