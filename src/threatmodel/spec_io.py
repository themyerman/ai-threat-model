"""Load and save system specs (YAML or JSON, chosen by file extension)."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from .models import SpecError, SystemSpec


def load_spec(path: str | Path) -> SystemSpec:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        raise SpecError(f"cannot read {path}: {err.strerror or err}") from err
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)  # safe_load only: specs are data, never code
    except (json.JSONDecodeError, yaml.YAMLError) as err:
        raise SpecError(f"{path} is not valid {path.suffix or 'YAML'}: {err}") from err
    return SystemSpec.from_dict(data)


def save_spec(spec: SystemSpec, path: str | Path) -> None:
    path = Path(path)
    data = spec.to_dict()
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    else:
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
