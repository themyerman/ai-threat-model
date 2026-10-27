"""Walk a person through Q1 and build a SystemSpec."""
from __future__ import annotations

from typing import Callable

from .models import ENFORCEMENT_KEYS, SCOPES, SOURCE_KINDS, Source, SystemSpec, Tool


def _yes(ask: Callable[[str], str], question: str) -> bool:
    while True:
        answer = ask(f"  {question} [y/n] ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def _choice(ask: Callable[[str], str], question: str, options: tuple[str, ...], default: str) -> str:
    while True:
        answer = ask(f"  {question} {options} [{default}] ").strip().lower() or default
        if answer in options:
            return answer


def _tool(ask, say, name: str) -> Tool:
    say(f"Tool '{name}':")
    return Tool(
        name=name,
        description=ask("  What does it do? ").strip(),
        reads_data=_yes(ask, "Reads customer or internal data?"),
        writes_data=_yes(ask, "Writes or edits anything?"),
        sends_external=_yes(ask, "Sends data out (email, SMS, webhook, link)?"),
        spends_money=_yes(ask, "Spends money?"),
        irreversible=_yes(ask, "Takes actions you cannot undo?"),
        human_approval=_yes(ask, "Does a human approve before it runs?"),
        credential_scope=_choice(ask, "Token scope?", SCOPES, "per_user"),
        standing_access=_yes(ask, "Keeps standing access between uses?"),
        separate_read_write_tokens=_yes(ask, "Separate tokens for reading and writing?"),
    )


def build_spec(ask: Callable[[str], str] = input, say: Callable[[str], None] = print) -> SystemSpec:
    say("Q1. What are we working on?")
    name = ask("System name: ").strip()
    purpose = ask("What does it do? ").strip()
    credentials = ask("Whose credentials do its tools run under? ").strip()

    tools: list[Tool] = []
    say("\nList the tools or APIs it can call (blank line to finish).")
    while (tool_name := ask("Tool name: ").strip()):
        tools.append(_tool(ask, say, tool_name))

    sources: list[Source] = []
    say("\nList every place untrusted text can reach it (blank line to finish).")
    while (source_name := ask("Source name: ").strip()):
        sources.append(Source(source_name, _choice(ask, "Kind?", SOURCE_KINDS, "other")))

    say("")
    memory = _yes(ask, "Does it keep memory between sessions?")
    rollup = _yes(ask, "Do its instructions or skill files update automatically from real activity?")
    say("\nWhich of these are enforced in code today, outside the model?")
    enforcement = {key: _yes(ask, f"{key}?") for key in ENFORCEMENT_KEYS}

    spec = SystemSpec(name=name, purpose=purpose, credentials=credentials, tools=tools,
                      sources=sources, memory=memory, config_rollup=rollup, enforcement=enforcement)
    # Round-trip through validation so interactive and file input obey the same rules.
    return SystemSpec.from_dict(spec.to_dict())
