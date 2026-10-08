"""Guardrails for text that attackers control.

Anyone who can create or edit an identity can choose its display name, description or notes, and
anyone who can edit an agent can choose its description and instructions. That text reaches the
explainer agent's context through tool results, so it is handled as data:

1. `screen` flags instruction-like phrases (a regex stand-in for a classifier such as Azure AI
   Content Safety Prompt Shields; see docs/components/explainer-agent.md for the limits).
2. `quote` wraps the text in <untrusted_data> tags and neutralises any closing tag inside it, so
   the model can tell data from instructions.
3. `validate_answer` checks the model's answer against facts computed by code (finding IDs that
   exist, no claim that risks are gone while findings remain) and the caller falls back to a
   template when it fails.
4. `html` escapes text for the static report."""

from __future__ import annotations

import html as _html
import re

PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"disregard (all |any )?(previous|prior|earlier)",
    r"\bsystem (note|prompt|message)\b",
    r"note to (any )?ai",
    r"assistant instruction",
    r"you are now",
    r"mark (all )?(findings|risks|issues) as (resolved|closed|fixed)",
    r"report that (this tenant|there) (has|have|are) no",
    r"pre-?approved by",
]
INJECTION = re.compile("|".join(f"(?:{p})" for p in PATTERNS), re.I)
TAG = re.compile(r"</?\s*untrusted_data\s*>", re.I)


def screen(text: str) -> list[str]:
    """Instruction-like phrases found in the text (empty list when clean)."""
    return [m.group(0) for m in INJECTION.finditer(text or "")]


def quote(text: str) -> str:
    return f"<untrusted_data>{TAG.sub('[tag removed]', text or '')}</untrusted_data>"


def field(text: str, guard: bool = True) -> str:
    return quote(text) if guard else (text or "")


def html(text: object) -> str:
    return _html.escape(str(text), quote=True)


CLAIMS_CLEAN = re.compile(r"no identity risks|all findings (are|have been) resolved|nothing to fix|pre-?approved", re.I)
FINDING_ID = re.compile(r"\b[PFE]\d{2}-\d{2}\b")


def validate_answer(text: str, cited: list[str], known_ids: set[str], open_findings: int) -> list[str]:
    issues = []
    unknown = sorted({x for x in cited + FINDING_ID.findall(text) if x not in known_ids})
    if unknown:
        issues.append(f"cites findings that do not exist: {unknown}")
    if open_findings and CLAIMS_CLEAN.search(text):
        issues.append(f"claims the tenant is clean while {open_findings} findings are open")
    if TAG.search(text):
        issues.append("echoes untrusted-data tags")
    return issues
