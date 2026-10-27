"""Data model for the threat modeling tool.

Everything the user types goes through strict validation here, because a
silently ignored typo in a security spec ("human_aproval: true") is worse
than a crash.
"""
from __future__ import annotations

import difflib
from dataclasses import asdict, dataclass, field
from typing import Any

CATEGORIES: dict[str, str] = {
    "prompt_injection": "Attacker text, typed directly or arriving in retrieved content, is followed as an instruction",
    "excessive_agency": "The agent can act further or spend more than the task needs, and nothing in code stops it",
    "data_exfiltration": "Real data leaves the system to a destination nobody authorized",
    "confused_deputy": "The agent uses access it legitimately holds, on the wrong target",
    "manipulation": "Role confusion, policy smuggling, reframing, crescendo escalation, obfuscation",
    "memory_poisoning": "Stored memory is overwritten or slowly drifted by attacker-influenced input",
    "config_poisoning": "Auto-updated skill files or config are poisoned through the data that feeds them",
    "unauthorized_write": "The agent writes to a shared resource that others will later trust",
    "lateral_pivot": "A trusted connection is reused to reach a system it was never meant to touch",
    "spoofing": "A fake vendor, sender, or confirmation is accepted as the real one",
    "elevation_of_privilege": "The agent grants itself authority nobody gave it",
}

LAYERS = ("code", "prompt")
SCOPES = ("per_resource", "per_user", "broad")
SOURCE_KINDS = ("web", "email", "ticket", "upload", "user_chat", "feed", "other")
ENFORCEMENT_KEYS = (
    "tool_allowlist",
    "schema_validation",
    "server_side_authz",
    "output_filtering",
    "audit_logging",
)
ANY_SOURCE = "(any untrusted source)"


class SpecError(ValueError):
    """The system spec is malformed. The message says where and how to fix it."""


def _check_keys(data: dict, allowed: set[str], where: str) -> None:
    for key in data:
        if key not in allowed:
            hint = difflib.get_close_matches(str(key), sorted(allowed), n=1)
            tip = f" Did you mean '{hint[0]}'?" if hint else ""
            raise SpecError(f"{where}: unknown field '{key}'.{tip}")


def _flag(data: dict, key: str, default: bool, where: str) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise SpecError(f"{where}: '{key}' must be true or false, got {value!r}")
    return value


def _text(data: dict, key: str, where: str, required: bool = False) -> str:
    value = data.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SpecError(f"{where}: '{key}' must be text, got {value!r}")
    value = value.strip()
    if required and not value:
        raise SpecError(f"{where}: '{key}' is required")
    return value


@dataclass
class Tool:
    name: str
    description: str = ""
    reads_data: bool = False
    writes_data: bool = False
    sends_external: bool = False
    spends_money: bool = False
    irreversible: bool = False
    human_approval: bool = False
    credential_scope: str = "per_user"
    standing_access: bool = False
    separate_read_write_tokens: bool = False

    @classmethod
    def from_dict(cls, data: Any, index: int) -> "Tool":
        if isinstance(data, str):
            data = {"name": data}
        where = f"tools[{index}]"
        if not isinstance(data, dict):
            raise SpecError(f"{where}: must be a name or a mapping")
        _check_keys(data, set(cls.__dataclass_fields__), where)
        name = _text(data, "name", where, required=True)
        where = f"tool '{name}'"
        scope = data.get("credential_scope", "per_user")
        if scope not in SCOPES:
            raise SpecError(f"{where}: credential_scope must be one of {SCOPES}, got {scope!r}")
        return cls(
            name=name,
            description=_text(data, "description", where),
            reads_data=_flag(data, "reads_data", False, where),
            writes_data=_flag(data, "writes_data", False, where),
            sends_external=_flag(data, "sends_external", False, where),
            spends_money=_flag(data, "spends_money", False, where),
            irreversible=_flag(data, "irreversible", False, where),
            human_approval=_flag(data, "human_approval", False, where),
            credential_scope=scope,
            standing_access=_flag(data, "standing_access", False, where),
            separate_read_write_tokens=_flag(data, "separate_read_write_tokens", False, where),
        )


@dataclass
class Source:
    """A place untrusted text can come from. Everything listed is untrusted."""

    name: str
    kind: str = "other"

    @classmethod
    def from_dict(cls, data: Any, index: int) -> "Source":
        if isinstance(data, str):
            data = {"name": data}
        where = f"sources[{index}]"
        if not isinstance(data, dict):
            raise SpecError(f"{where}: must be a name or a mapping")
        _check_keys(data, {"name", "kind"}, where)
        name = _text(data, "name", where, required=True)
        kind = data.get("kind", "other")
        if kind not in SOURCE_KINDS:
            raise SpecError(f"source '{name}': kind must be one of {SOURCE_KINDS}, got {kind!r}")
        return cls(name=name, kind=kind)


@dataclass
class SystemSpec:
    name: str
    purpose: str = ""
    credentials: str = ""
    tools: list[Tool] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    memory: bool = False
    config_rollup: bool = False
    enforcement: dict[str, bool] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> "SystemSpec":
        if not isinstance(data, dict):
            raise SpecError("spec must be a mapping at the top level")
        allowed = {"name", "purpose", "credentials", "tools", "sources",
                   "memory", "config_rollup", "enforcement"}
        _check_keys(data, allowed, "spec")
        name = _text(data, "name", "spec", required=True)

        def seq(key: str) -> list:
            raw = data.get(key)
            if not isinstance(raw, list) or not raw:
                raise SpecError(f"spec: '{key}' must be a non-empty list")
            return raw

        tools = [Tool.from_dict(t, i) for i, t in enumerate(seq("tools"))]
        sources = [Source.from_dict(s, i) for i, s in enumerate(seq("sources"))]
        for label, items in (("tool", tools), ("source", sources)):
            names = [i.name for i in items]
            dupes = sorted({n for n in names if names.count(n) > 1})
            if dupes:
                raise SpecError(f"spec: duplicate {label} names: {dupes}")

        enforcement_raw = data.get("enforcement") or {}
        if not isinstance(enforcement_raw, dict):
            raise SpecError("spec: 'enforcement' must be a mapping")
        _check_keys(enforcement_raw, set(ENFORCEMENT_KEYS), "enforcement")
        enforcement = {k: _flag(enforcement_raw, k, False, "enforcement") for k in ENFORCEMENT_KEYS}

        return cls(
            name=name,
            purpose=_text(data, "purpose", "spec"),
            credentials=_text(data, "credentials", "spec"),
            tools=tools,
            sources=sources,
            memory=_flag(data, "memory", False, "spec"),
            config_rollup=_flag(data, "config_rollup", False, "spec"),
            enforcement=enforcement,
        )

    def to_dict(self) -> dict:
        return asdict(self)

    def tool(self, name: str) -> Tool:
        return next(t for t in self.tools if t.name == name)


@dataclass
class Control:
    layer: str  # "code" or "prompt"
    text: str


@dataclass
class Threat:
    category: str
    entry_point: str
    target: str
    scenario: str
    likelihood: int
    impact: int
    origin: str = "rule"  # "rule" (deterministic) or "llm"
    id: str = ""
    controls: list[Control] = field(default_factory=list)
    # When one threat covers several sources at once (same attack, same target),
    # their names live here and entry_point shows them joined.
    entries: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    def source_names(self) -> list[str]:
        """The specific sources this threat covers (empty for 'any untrusted source')."""
        if self.entries:
            return list(self.entries)
        return [] if self.entry_point == ANY_SOURCE else [self.entry_point]

    @property
    def has_code_control(self) -> bool:
        return any(c.layer == "code" for c in self.controls)

    def key(self) -> tuple[str, str, str]:
        return (self.category, self.entry_point, self.target)


@dataclass
class ThreatModel:
    spec: SystemSpec
    threats: list[Threat]  # ranked, truncated, ids assigned
    omitted: int = 0  # threats found but below the cut
    llm_used: bool = False

    def to_dict(self) -> dict:
        return {
            "spec": self.spec.to_dict(),
            "llm_used": self.llm_used,
            "omitted": self.omitted,
            "threats": [dict(asdict(t), score=t.score) for t in self.threats],
        }
