"""Deterministic threat rules.

These need no LLM. They read the system spec and emit findings, each with
controls that live in code. This is the 80/20 layer: it catches the common
shortcuts (broad tokens, no approval gate, bundled read/write) every time,
with the same answer on every run.
"""
from __future__ import annotations

from typing import Callable

from .models import ANY_SOURCE, Control, SystemSpec, Threat, Tool

BOUNDARY_KEYS = ("tool_allowlist", "schema_validation", "server_side_authz", "output_filtering")


def tool_impact(tool: Tool) -> int:
    """How bad is it if this tool does the wrong thing? 2 (read-only) to 5."""
    if tool.spends_money or tool.irreversible:
        return 5
    if tool.sends_external:
        return 4
    if tool.writes_data:
        return 3
    return 2


def _riskiest(spec: SystemSpec) -> Tool:
    return max(spec.tools, key=tool_impact)


def indirect_injection(spec: SystemSpec) -> list[Threat]:
    """One threat for typed (direct) sources and one for retrieved (indirect) ones.

    Merging keeps the ranking readable: four review-like sources are one attack,
    not four. Per-source coverage is still tracked through Threat.entries.
    """
    target = _riskiest(spec)
    groups = {
        True: [s.name for s in spec.sources if s.kind == "user_chat"],
        False: [s.name for s in spec.sources if s.kind != "user_chat"],
    }
    out = []
    for direct, names in groups.items():
        if not names:
            continue
        joined = ", ".join(names)
        how = "typed straight into the chat" if direct else "hidden in content the system retrieves"
        out.append(Threat(
            category="prompt_injection",
            entry_point=joined,
            entries=names,
            target=target.name,
            scenario=(f"Attacker instructions {how} (via {joined}) are followed as commands "
                      f"and steer '{target.name}'."),
            likelihood=4 if direct else 5,
            impact=tool_impact(target),
            controls=[
                Control("code", f"Treat everything from {joined} as data, never instructions, in "
                                f"prompt and in code; gate every call to '{target.name}' behind an "
                                "allowlist and schema check."),
                Control("prompt", f"Put a SECURITY NOTICE immediately before content from {joined} "
                                  "(one layer, never the boundary)."),
            ],
        ))
    return out


def exfiltration(spec: SystemSpec) -> list[Threat]:
    out = []
    filtered = spec.enforcement.get("output_filtering", False)
    for tool in spec.tools:
        if not tool.sends_external:
            continue
        out.append(Threat(
            category="data_exfiltration",
            entry_point=ANY_SOURCE,
            target=tool.name,
            scenario=(f"Injected content makes '{tool.name}' send data to a destination the user "
                      "never named (an address, a link, an image URL)."),
            likelihood=2 if filtered else 4,
            impact=5 if tool.reads_data else 4,
            controls=[
                Control("code", f"Recipient allowlist for '{tool.name}': only destinations on the "
                                "verified customer's own record; block and flag multi-record outputs."),
                Control("code", "Output check for unfamiliar domains and data embedded in generated links."),
            ],
        ))
    return out


def unapproved_actions(spec: SystemSpec) -> list[Threat]:
    out = []
    for tool in spec.tools:
        if (tool.spends_money or tool.irreversible) and not tool.human_approval:
            out.append(Threat(
                category="excessive_agency",
                entry_point=ANY_SOURCE,
                target=tool.name,
                scenario=(f"'{tool.name}' can spend money or take an irreversible action with no "
                          "human checkpoint, so one bad decision runs to completion."),
                likelihood=4,
                impact=5,
                controls=[Control("code", f"Human approval above a set threshold for '{tool.name}', "
                                          "plus a hard spend cap enforced server-side.")],
            ))
    return out


def broad_credentials(spec: SystemSpec) -> list[Threat]:
    out = []
    for tool in spec.tools:
        if tool.credential_scope == "per_resource":
            continue
        broad = tool.credential_scope == "broad"
        out.append(Threat(
            category="confused_deputy",
            entry_point=ANY_SOURCE,
            target=tool.name,
            scenario=(f"'{tool.name}' runs on a {'broad' if broad else 'per-user'} credential, so a "
                      "tricked agent can act on someone else's records using access it legitimately has."),
            likelihood=4 if broad else 3,
            impact=max(tool_impact(tool), 4),
            controls=[Control("code", f"Scope '{tool.name}' tokens per resource; let server-side "
                                      "authorization decide each request, never the model.")],
        ))
    return out


def bundled_read_write(spec: SystemSpec) -> list[Threat]:
    out = []
    for tool in spec.tools:
        if tool.reads_data and tool.writes_data and not tool.separate_read_write_tokens:
            out.append(Threat(
                category="unauthorized_write",
                entry_point=ANY_SOURCE,
                target=tool.name,
                scenario=(f"'{tool.name}' reads and writes on one token, so an injected instruction "
                          "can edit a resource the agent was only meant to summarize."),
                likelihood=3,
                impact=4,
                controls=[Control("code", f"Issue separate read and write tokens for '{tool.name}', or "
                                          "an action allowlist that permits read only. Do both.")],
            ))
    return out


def standing_access(spec: SystemSpec) -> list[Threat]:
    out = []
    for tool in spec.tools:
        if tool.standing_access and (tool.sends_external or tool.writes_data):
            out.append(Threat(
                category="lateral_pivot",
                entry_point=ANY_SOURCE,
                target=tool.name,
                scenario=(f"'{tool.name}' keeps standing access, so an injected instruction can reuse "
                          "that open connection to reach a system it was never meant to touch."),
                likelihood=3,
                impact=4,
                controls=[Control("code", f"Make '{tool.name}' access single-use and expiring; require "
                                          "a fresh, narrowly scoped grant (with a human) per use.")],
            ))
    return out


def memory_drift(spec: SystemSpec) -> list[Threat]:
    if not spec.memory:
        return []
    target = max(spec.tools, key=lambda t: (t.writes_data, tool_impact(t)))
    return [Threat(
        category="memory_poisoning",
        entry_point=ANY_SOURCE,
        target=target.name,
        scenario=("Stored memory (preferences, allergies, accessibility needs) is overwritten, or "
                  "drifts through many small edits, and later decisions rely on it."),
        likelihood=3,
        impact=4,
        controls=[Control("code", "Log and diff memory writes; require confirmation before "
                                  "safety-relevant fields are overwritten.")],
    )]


def config_rollup(spec: SystemSpec) -> list[Threat]:
    if not spec.config_rollup:
        return []
    return [Threat(
        category="config_poisoning",
        entry_point=ANY_SOURCE,
        target=_riskiest(spec).name,
        scenario=("Skill files or operating instructions refresh automatically from real activity, "
                  "so poisoning the activity poisons next week's defaults."),
        likelihood=2,
        impact=5,
        controls=[Control("code", "Review auto-generated config updates like a pull request and "
                                  "diff against the last known-good version before they ship.")],
    )]


def model_is_the_boundary(spec: SystemSpec) -> list[Threat]:
    missing = [k for k in BOUNDARY_KEYS if not spec.enforcement.get(k, False)]
    if not missing:
        return []
    target = _riskiest(spec)
    return [Threat(
        category="manipulation",
        entry_point=ANY_SOURCE,
        target=target.name,
        scenario=("Role confusion, policy smuggling, reframing, and crescendo only need to persuade "
                  f"the model; no code-level enforcement exists for: {', '.join(missing)}."),
        likelihood=5 if len(missing) >= 3 else 4,
        impact=max(tool_impact(target), 4),
        controls=[Control("code", f"Enforce outside the model: {', '.join(missing)}.")],
    )]


RULES: list[Callable[[SystemSpec], list[Threat]]] = [
    indirect_injection,
    exfiltration,
    unapproved_actions,
    broad_credentials,
    bundled_read_write,
    standing_access,
    memory_drift,
    config_rollup,
    model_is_the_boundary,
]


def evaluate(spec: SystemSpec) -> list[Threat]:
    findings: list[Threat] = []
    for rule in RULES:
        findings.extend(rule(spec))
    return findings
