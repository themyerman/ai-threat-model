"""Render a ThreatModel as Markdown or JSON."""
from __future__ import annotations

import json

from .models import ENFORCEMENT_KEYS, ThreatModel

RE_REVIEW = (
    "A tool or data source is added or changes its permissions",
    "Credentials or token scopes change",
    "The model, system prompt, or retrieval pipeline changes",
    "Any incident or near miss, however small",
)


def _yn(value: bool) -> str:
    return "yes" if value else "**no**"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def to_json(model: ThreatModel) -> str:
    return json.dumps(model.to_dict(), indent=2)


def to_markdown(model: ThreatModel) -> str:
    spec = model.spec
    lines = [f"# Threat model: {spec.name}", ""]
    if not model.llm_used:
        lines += ["> Rules only: no LLM was used, so this covers the common shortcuts but not "
                  "anything specific to what this system does.", ""]
    elif model.llm_label.startswith("mock"):
        lines += ["> Mock mode: the LLM stages ran against canned, deterministic replies, not a "
                  "real model. Threats marked `llm` are templates. Use this to see how the "
                  "pipeline works, not to judge a system.", ""]
    else:
        lines += [f"_LLM stages: {model.llm_label}._", ""]

    # Q1
    lines += ["## Q1. What are we working on?", ""]
    if spec.purpose:
        lines += [spec.purpose, ""]
    if spec.credentials:
        lines += [f"Credentials: {spec.credentials}", ""]
    lines += ["| Tool | Reads | Writes | Sends out | Spends | Irreversible | Approval | Token scope |",
              "|---|---|---|---|---|---|---|---|"]
    for t in spec.tools:
        lines.append(f"| {_cell(t.name)} | {_yn(t.reads_data)} | {_yn(t.writes_data)} | "
                     f"{_yn(t.sends_external)} | {_yn(t.spends_money)} | {_yn(t.irreversible)} | "
                     f"{_yn(t.human_approval)} | {t.credential_scope} |")
    lines += ["", "Untrusted sources: " + ", ".join(f"{s.name} ({s.kind})" for s in spec.sources), ""]

    # Q2
    lines += ["## Q2. What can go wrong?", "",
              "| ID | Score | Category | Entry point | Target | Found by |",
              "|---|---|---|---|---|---|"]
    for t in model.threats:
        lines.append(f"| {t.id} | {t.score} ({t.likelihood}x{t.impact}) | {t.category} | "
                     f"{_cell(t.entry_point)} | {_cell(t.target)} | {t.origin} |")
    if model.omitted:
        lines += ["", f"_{model.omitted} lower-scoring threat(s) omitted. Raise --top to see them._"]
    lines.append("")
    for t in model.threats:
        lines.append(f"- **{t.id}**: {t.scenario}")

    # Q3
    lines += ["", "## Q3. What are we going to do about it?", ""]
    for t in model.threats:
        lines.append(f"### {t.id}: {t.category} ({t.entry_point} -> {t.target})")
        for c in t.controls:
            lines.append(f"- [{c.layer}] {c.text}")
        if not t.has_code_control:
            lines.append("- **No code-level control. Everything here depends on the model behaving.**")
        lines.append("")
    prompt_only = [t.id for t in model.threats if not t.has_code_control]
    lines += ["### Enforcement in code today", "", "| Control | In place |", "|---|---|"]
    for key in ENFORCEMENT_KEYS:
        lines.append(f"| {key} | {_yn(spec.enforcement.get(key, False))} |")

    # Q4
    lines += ["", "## Q4. Did we do a good job?", "",
              "A human answers this one. Start with:", "",
              "- Which of these controls still hold if the model believes every word it reads?",
              "- Who owns each control, and how will we know it failed?",
              "- What did we not model because nobody in the room knew about it?", ""]
    if not spec.enforcement.get("audit_logging", False):
        lines += ["Audit logging is off: if something goes wrong you cannot trace which input "
                  "triggered which action. Fix that first.", ""]
    if prompt_only:
        lines += [f"Threats with no code-level control: {', '.join(prompt_only)}.", ""]
    lines += ["Re-review when:"] + [f"- {r}" for r in RE_REVIEW]
    lines += ["", "_Scores are estimates. Treat the ranking as a conversation starter, not a verdict._", ""]
    return "\n".join(lines)
