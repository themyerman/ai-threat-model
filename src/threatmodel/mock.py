"""A stand-in model for running the whole pipeline with no key and no network.

It reads the <untrusted> data block a real model would get and answers with
canned, deterministic JSON. Its replies go through exactly the same validation
as a real model's, so mock mode shows how the pipeline works. It is not
analysis: the scenarios are templates, and the report says so.
"""
from __future__ import annotations

import json
import re

from .models import CATEGORIES, Tool
from .rules import tool_impact

# Which kinds of attack each kind of source suggests first.
PREFERRED = {
    "web": ("spoofing", "data_exfiltration", "prompt_injection"),
    "email": ("spoofing", "data_exfiltration"),
    "ticket": ("elevation_of_privilege", "spoofing"),
    "upload": ("prompt_injection", "data_exfiltration"),
    "user_chat": ("manipulation", "elevation_of_privilege"),
    "feed": ("unauthorized_write", "config_poisoning"),
    "other": ("spoofing",),
}

SCENARIOS = {
    "prompt_injection": "Instructions planted in {source} are read as commands and steer '{tool}'.",
    "excessive_agency": "Content from {source} pushes '{tool}' to do far more than the task asked.",
    "data_exfiltration": "A link or address planted in {source} gets '{tool}' to carry real data out.",
    "confused_deputy": "A request arriving via {source} gets '{tool}' to act on someone else's records.",
    "manipulation": "A slow, friendly escalation through {source} talks the agent into misusing '{tool}'.",
    "memory_poisoning": "Claims repeated through {source} end up in stored memory and skew '{tool}' later.",
    "config_poisoning": "Patterns seeded in {source} flow into auto-updated config that steers '{tool}'.",
    "unauthorized_write": "Text in {source} gets '{tool}' to edit a shared record that others then trust.",
    "lateral_pivot": "A message in {source} gets the agent to reuse '{tool}' against a system it should not touch.",
    "spoofing": "A fake sender or confirmation in {source} is accepted as genuine, and '{tool}' acts on it.",
    "elevation_of_privilege": "A claim of authority in {source} gets the agent to unlock '{tool}' for itself.",
}

CODE_CONTROLS = {
    "prompt_injection": "Allowlist the actions and arguments '{tool}' accepts and reject everything else server-side.",
    "excessive_agency": "Hard per-request limits on '{tool}' (count, amount, scope), enforced server-side.",
    "data_exfiltration": "Recipient and domain allowlist on everything '{tool}' sends out.",
    "confused_deputy": "Per-resource tokens for '{tool}'; server-side authorization decides each request.",
    "manipulation": "Schema-validate every '{tool}' call and require human approval above a threshold.",
    "memory_poisoning": "Log and diff memory writes that feed '{tool}'; confirm safety-relevant changes.",
    "config_poisoning": "Review auto-generated config like a pull request before '{tool}' uses it.",
    "unauthorized_write": "Read-only token by default for '{tool}'; writes need a separate, scoped grant.",
    "lateral_pivot": "Single-use, expiring credentials for '{tool}', scoped to one destination.",
    "spoofing": "Verify sender identity out of band before '{tool}' acts on any confirmation.",
    "elevation_of_privilege": "Permissions for '{tool}' come from the identity provider, never from content.",
}

LABEL = "mock (canned replies, not a real model)"


def _payload(messages: list[dict]) -> dict:
    """The data block from the first user message; retries keep it in place."""
    text = messages[0]["content"]
    match = re.search(r"<untrusted>\n(.*)\n</untrusted>", text, flags=re.DOTALL)
    if not match:
        raise ValueError("mock: no <untrusted> block in the prompt")
    return json.loads(match.group(1))


class MockLLM:
    label = LABEL

    def complete(self, system: str, messages: list[dict]) -> str:
        data = _payload(messages)
        if "must_cover" in data:
            return json.dumps({"threats": self._threats(data)})
        return json.dumps({"controls": self._controls(data)})

    def _threats(self, data: dict) -> list[dict]:
        system = data["system"]
        tools = {t["name"]: Tool(**t) for t in system["tools"]}
        kinds = {s["name"]: s["kind"] for s in system["sources"]}
        gap_tools = data["must_cover"]["tools"]
        gap_sources = data["must_cover"]["sources"]
        # Avoid any (category, tool) pair already found, so nothing reads as a repeat.
        taken = {(t["category"], t["target"]) for t in data["already_found"]}
        names = list(tools)
        out = []
        for i in range(max(len(gap_tools), len(gap_sources))):
            source = gap_sources[i % len(gap_sources)] if gap_sources else next(iter(kinds))
            first = gap_tools[i] if i < len(gap_tools) else names[i % len(names)]
            categories = PREFERRED[kinds[source]] + tuple(CATEGORIES)
            pick = next(((c, t) for t in [first] + names for c in categories if (c, t) not in taken), None)
            if pick is None:
                continue
            category, tool = pick
            taken.add(pick)
            out.append({
                "category": category, "entry_point": source, "target": tool,
                "scenario": SCENARIOS[category].format(source=source, tool=tool),
                "likelihood": 3, "impact": tool_impact(tools[tool]),
            })
        return out

    def _controls(self, data: dict) -> list[dict]:
        out = []
        for t in data["threats"]:
            out.append({"threat_id": t["id"], "layer": "code",
                        "text": CODE_CONTROLS[t["category"]].format(tool=t["target"])})
            out.append({"threat_id": t["id"], "layer": "prompt",
                        "text": f"Mark content from {t['entry_point']} as data, never instructions "
                                "(one layer, never the boundary)."})
        return out
