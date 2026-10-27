"""Export a ThreatModel for use elsewhere: a Mermaid data-flow diagram, and an
OWASP Threat Dragon (v2) model that opens as an editable diagram.

Both draw the same picture: untrusted sources -> the agent -> its tools, plus
memory and auto-updated config as stores when the spec has them.
"""
from __future__ import annotations

import json
import uuid

from .models import Threat, ThreatModel

# --- Mermaid ---------------------------------------------------------------

SEVERITY_CLASSES = (
    "classDef high fill:#ffd6d6,stroke:#b00020,color:#000",
    "classDef medium fill:#fff1c2,stroke:#a06000,color:#000",
)


def _label(text: str) -> str:
    """Spec names are user text; keep them from breaking out of a Mermaid label."""
    return (text.replace("&", "#amp;").replace('"', "#quot;")
            .replace("<", "#lt;").replace(">", "#gt;"))


def severity(score: int) -> str:
    """One scale for both exports, matching Threat Dragon's High / Medium / Low."""
    return "High" if score >= 15 else "Medium" if score >= 8 else "Low"


def _severity_class(threats: list[Threat]) -> str | None:
    worst = severity(max((t.score for t in threats), default=0))
    return {"High": "high", "Medium": "medium"}.get(worst)


def _edge(a: str, b: str, threats: list[Threat], arrow: str = "-->") -> str:
    ids = " ".join(t.id for t in threats)
    return f"    {a} {arrow}|{ids}| {b}" if ids else f"    {a} {arrow} {b}"


def to_mermaid(model: ThreatModel) -> str:
    """A left-to-right data-flow diagram. Edge labels are threat IDs from the report;
    nodes are shaded by the worst threat that touches them."""
    spec, threats = model.spec, model.threats
    lines = ["flowchart LR", '    subgraph untrusted["Untrusted sources"]']
    for i, s in enumerate(spec.sources):
        lines.append(f'        s{i}["{_label(s.name)}<br/><small>{s.kind}</small>"]')
    lines += ["    end", f'    agent(["{_label(spec.name)}"])', '    subgraph tools["Tools"]']
    for i, t in enumerate(spec.tools):
        lines.append(f'        t{i}["{_label(t.name)}"]')
    lines.append("    end")

    classes: dict[str, str] = {}
    for i, s in enumerate(spec.sources):
        hits = [t for t in threats if s.name in t.source_names()]
        lines.append(_edge(f"s{i}", "agent", hits))
    for i, tool in enumerate(spec.tools):
        hits = [t for t in threats if t.target == tool.name]
        lines.append(_edge("agent", f"t{i}", hits))
        if cls := _severity_class(hits):
            classes[f"t{i}"] = cls
    if spec.memory:
        hits = [t for t in threats if t.category == "memory_poisoning"]
        lines += ['    mem[("Memory")]', _edge("agent", "mem", hits, "<-->")]
    if spec.config_rollup:
        hits = [t for t in threats if t.category == "config_poisoning"]
        lines += ['    cfg[("Auto-updated config")]', "    agent -. activity .-> cfg",
                  _edge("cfg", "agent", hits)]

    lines += [f"    {c}" for c in SEVERITY_CLASSES]
    for node, cls in classes.items():
        lines.append(f"    class {node} {cls}")
    return "\n".join(lines)


# --- OWASP Threat Dragon v2 ------------------------------------------------
# Format checked against the threat-dragon-v2 JSON schema and demo models in
# OWASP/threat-dragon v2.6.2. Threats use the STRIDE methodology, so each AI
# category is mapped to the STRIDE type it is closest to; the AI category
# stays in the threat title.

STRIDE = {
    "prompt_injection": "Tampering",
    "excessive_agency": "Elevation of privilege",
    "data_exfiltration": "Information disclosure",
    "confused_deputy": "Elevation of privilege",
    "manipulation": "Tampering",
    "memory_poisoning": "Tampering",
    "config_poisoning": "Tampering",
    "unauthorized_write": "Tampering",
    "lateral_pivot": "Elevation of privilege",
    "spoofing": "Spoofing",
    "elevation_of_privilege": "Elevation of privilege",
}
TD_VERSION = "2.0.0"
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "threatmodel/threat-dragon")  # fixed, so exports are stable


def _id(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "/".join(parts)))


def _td_threat(model: ThreatModel, t: Threat) -> dict:
    mitigation = "\n".join(f"[{c.layer}] {c.text}" for c in t.controls)
    if not t.has_code_control:
        mitigation += "\nNo code-level control yet: everything here depends on the model behaving."
    return {
        "id": _id(model.spec.name, "threat", t.id, *t.key()),
        "title": f"{t.id} {t.category}",
        "number": int(t.id[1:]),  # Threat Dragon shows "Edit Threat #<number>"; not in its schema
        "type": STRIDE[t.category],
        "modelType": "STRIDE",
        "status": "Open",
        "severity": severity(t.score),
        "description": (f"{t.scenario}\n\nEntry point: {t.entry_point}. Score {t.score} "
                        f"(likelihood {t.likelihood} x impact {t.impact}). Found by: {t.origin}."),
        "mitigation": mitigation.strip(),
        "score": str(t.score),
    }


def _node(model: ThreatModel, key: str, shape: str, name: str, x: int, y: int,
          threats: list[Threat], description: str = "", **flags) -> dict:
    td_type = {"actor": "tm.Actor", "process": "tm.Process", "store": "tm.Store"}[shape]
    w, h = (100, 100) if shape == "process" else (160, 80)
    red = any(t.score >= 15 for t in threats)
    stroke = {"stroke": "red" if threats else "#333333", "strokeWidth": 3 if red else 1,
              "strokeDasharray": None}
    attrs = {"text": {"text": name}}
    if shape == "store":
        attrs |= {"topLine": dict(stroke), "bottomLine": dict(stroke)}
    else:
        attrs["body"] = stroke
    return {
        "id": _id(model.spec.name, key), "shape": shape, "zIndex": 1,
        "position": {"x": x, "y": y}, "size": {"width": w, "height": h}, "attrs": attrs,
        "data": {"name": name, "description": description, "type": td_type,
                 "isTrustBoundary": False, "outOfScope": False, "reasonOutOfScope": "",
                 "threats": [_td_threat(model, t) for t in threats],
                 "hasOpenThreats": bool(threats), **flags},
    }


def _flow(model: ThreatModel, key: str, name: str, source: dict, target: dict) -> dict:
    return {
        "id": _id(model.spec.name, key), "shape": "flow", "zIndex": 10, "connector": "smooth",
        "width": 200, "height": 100,
        "attrs": {"line": {"stroke": "#333333", "strokeWidth": 1,
                           "targetMarker": {"name": "block"}, "strokeDasharray": None}},
        "labels": [{"position": 0.5, "attrs": {"label": {"text": name}}}],
        "source": {"cell": source["id"]}, "target": {"cell": target["id"]},
        "data": {"type": "tm.Flow", "name": name, "description": "", "outOfScope": False,
                 "reasonOutOfScope": "", "protocol": "", "isEncrypted": False,
                 "isPublicNetwork": False, "isTrustBoundary": False,
                 "hasOpenThreats": False, "threats": []},
    }


def to_threat_dragon(model: ThreatModel) -> str:
    """Threats sit on the element they target: the tool, or the memory/config store."""
    spec, threats = model.spec, model.threats
    on_store = {"memory_poisoning": spec.memory, "config_poisoning": spec.config_rollup}
    row = 130
    rows = max(len(spec.sources), len(spec.tools))
    cells: list[dict] = []

    agent = _node(model, "agent", "process", spec.name, 420, 40 + (rows - 1) * row // 2, [],
                  spec.purpose)
    cells.append(agent)
    for i, s in enumerate(spec.sources):
        actor = _node(model, f"source/{s.name}", "actor", s.name, 40, 40 + i * row, [],
                      f"Untrusted source ({s.kind}).", providesAuthentication=False)
        cells += [actor, _flow(model, f"flow/source/{s.name}", "untrusted content", actor, agent)]
    for i, tool in enumerate(spec.tools):
        hits = [t for t in threats if t.target == tool.name and not on_store.get(t.category)]
        node = _node(model, f"tool/{tool.name}", "process", tool.name, 760, 40 + i * row, hits,
                     tool.description)
        cells += [node, _flow(model, f"flow/tool/{tool.name}", "tool call", agent, node)]
    stores = (("memory", spec.memory, "Memory", "memory_poisoning"),
              ("config", spec.config_rollup, "Auto-updated config", "config_poisoning"))
    for n, (key, present, name, category) in enumerate(stores):
        if not present:
            continue
        hits = [t for t in threats if t.category == category]
        store = _node(model, f"store/{key}", "store", name, 340 + n * 220, 40 + rows * row, hits,
                      isALog=False, storesCredentials=False, isEncrypted=False, isSigned=False)
        cells += [store, _flow(model, f"flow/store/{key}", "reads and writes", agent, store)]

    # The trust boundary sits between the untrusted sources and the agent.
    bottom = 40 + rows * row
    cells.append({
        "id": _id(spec.name, "boundary"), "shape": "trust-boundary-curve", "zIndex": 10,
        "connector": "smooth", "width": 200, "height": 100,
        "attrs": {"line": {"targetMarker": "", "sourceMarker": ""}},
        "labels": [{"attrs": {"text": {"text": "trust boundary"}}}],
        "source": {"x": 300, "y": 10}, "target": {"x": 300, "y": bottom},
        "data": {"type": "tm.Boundary", "name": "trust boundary", "description": "",
                 "isTrustBoundary": True, "hasOpenThreats": False},
    })

    note = (f"Generated by threatmodel (tm): top {len(threats)} threats"
            + (f", {model.omitted} lower-scoring omitted" if model.omitted else "")
            + (f"; LLM stages: {model.llm_label}" if model.llm_used else "; rules only") + ".")
    doc = {
        "version": TD_VERSION,
        "summary": {"title": f"Threat model: {spec.name}", "owner": "",
                    "description": f"{spec.purpose}\n\n{note}".strip(), "id": 0},
        "detail": {
            "contributors": [], "reviewer": "", "diagramTop": 1, "threatTop": len(threats),
            "diagrams": [{
                "id": 0, "version": TD_VERSION, "diagramType": "STRIDE",
                "title": f"{spec.name} data flow", "description": note,
                "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                "cells": cells,
            }],
        },
    }
    return json.dumps(doc, indent=2)
