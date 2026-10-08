# Contributing

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

```bash
ruff check . && ruff format --check .
pytest -q
idsec gate
idsec synth --check
python scripts/render_docs.py --check
```

If you change the generator, run `idsec synth` and update `data/ground-truth.json` through the generator,
never by hand. If you change anything that affects output, run `python scripts/render_docs.py` to refresh
the rendered blocks, and update any hand-written number that quotes them.

For infrastructure changes also run `terraform fmt -recursive`, `terraform test` and `tflint` in
`infra/terraform`, `checkov -d infra/terraform --config-file .checkov.yaml`, and `bicep build` on every
file in `infra/bicep`.

## Rules

- Fictional organisation and synthetic data only: `.example` domains and mock IDs starting with
  `00000000-`. No real people, tenants or subscriptions.
- A new rule needs: an entry in `detections/rules.yaml` with mappings, an implementation in
  `src/idsec/detections.py`, a planted case and a look-alike in `src/idsec/synth.py`, a mutation test,
  and a remediation action.
- Product code must not import `idsec.labels` or `idsec.metrics`; the release gate checks this.
- Collectors stay read-only: new endpoints must pass `collectors/http.check` and need a matching read
  action in `infra/role/identity-posture-reader.json`.
- Never commit third-party documents (`*.pdf` is ignored and a test checks it). Use your own words and
  run `python scripts/overlap_check.py <reference text>` on new prose; expect zero shared eight-word runs.
- No dates, years or month names in markdown, and no placeholder words; component and infra docs need all
  16 sections. `tests/test_repo_hygiene.py` checks these.
- Keep the honest labels: built, written but not run, planned. Never describe anything as deployed.
