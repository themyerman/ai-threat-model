import json
from importlib import resources

import pytest
import yaml

from threatmodel.models import SystemSpec


@pytest.fixture
def raw_spec():
    text = resources.files("threatmodel").joinpath("data/victoriabot.yaml").read_text(encoding="utf-8")
    return yaml.safe_load(text)


@pytest.fixture
def spec(raw_spec):
    return SystemSpec.from_dict(raw_spec)


class FakeLLM:
    """Returns scripted replies in order and records what it was sent."""

    def __init__(self, *replies):
        self.replies = [r if isinstance(r, str) else json.dumps(r) for r in replies]
        self.calls = []

    def complete(self, system, messages):
        self.calls.append((system, [dict(m) for m in messages]))
        return self.replies.pop(0)


def threat_json(spec, **over):
    base = {"category": "spoofing", "entry_point": spec.sources[0].name,
            "target": spec.tools[0].name,
            "scenario": "A fake operator page is accepted as the real one and listed.",
            "likelihood": 3, "impact": 3}
    base.update(over)
    return base
