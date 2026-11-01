# scripts

| File | What it does |
|---|---|
| `render_docs.py` | Rewrites `<!-- output: ... -->` and `<!-- code: ... -->` blocks in every markdown file from a fresh run; `--check` fails CI if any block is stale |
| `overlap_check.py` | Reports any 8-word run shared between the repository and reference texts kept outside it, to prove nothing was copied |
| `brand_check.py` | Fails CI if any file contains a real company name from a blocklist stored only as SHA-256 hashes |
