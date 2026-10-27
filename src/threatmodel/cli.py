"""Command line interface: tm demo | init | lint | run | interactive."""
from __future__ import annotations

import argparse
import os
import sys
from importlib import resources
from pathlib import Path

import yaml

from . import export, pipeline, report
from .interactive import build_spec
from .llm import BACKENDS, LLMError, make_llm
from .models import SpecError, SystemSpec
from .spec_io import load_spec, save_spec


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)


def _int_in(low: int, high: int | None = None):
    """argparse type: an integer in [low, high], so bad values fail at parse time."""
    def parse(text: str) -> int:
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
        if value < low or (high is not None and value > high):
            bound = f"from {low} to {high}" if high is not None else f"at least {low}"
            raise argparse.ArgumentTypeError(f"must be {bound}, got {value}")
        return value
    return parse


def _finish(spec: SystemSpec, args: argparse.Namespace, use_llm: bool) -> int:
    llm = make_llm(args.llm, model=args.model, base_url=args.base_url) if use_llm else None
    model = pipeline.run(spec, llm=llm, top_n=args.top)
    _emit(report.to_markdown(model), args.out)
    for path, render in ((args.json, report.to_json), (args.mermaid, export.to_mermaid),
                         (args.threat_dragon, export.to_threat_dragon)):
        if path:
            Path(path).write_text(render(model) + "\n", encoding="utf-8")
            print(f"wrote {path}")
    fail_on = getattr(args, "fail_on", 0)
    if fail_on and any(t.score >= fail_on for t in model.threats):
        print(f"FAIL: at least one threat scores {fail_on} or higher", file=sys.stderr)
        return 1
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    dest = Path(args.path)
    if dest.exists() and not args.force:
        print(f"{dest} already exists. Use --force to overwrite.", file=sys.stderr)
        return 2
    example = resources.files("threatmodel").joinpath("data/victoriabot.yaml")
    dest.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"wrote {dest}. Edit it, then run: tm lint {dest}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Everything at once on the VictoriaBot example: no spec, no flags, no key (mock by default)."""
    example = resources.files("threatmodel").joinpath("data/victoriabot.yaml")
    spec = SystemSpec.from_dict(yaml.safe_load(example.read_text(encoding="utf-8")))
    llm = make_llm(args.llm, model=args.model, base_url=args.base_url)
    print(f"Threat modeling the VictoriaBot example. LLM: {llm.label}")
    model = pipeline.run(spec, llm=llm, top_n=12)

    out = Path(args.dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "report.md": (report.to_markdown, "the four-question report, with a data-flow diagram"),
        "flow.mmd": (export.to_mermaid, "the diagram alone; paste it into https://mermaid.live"),
        "model.td.json": (export.to_threat_dragon,
                          "open in OWASP Threat Dragon (threatdragon.com, Local Session)"),
        "model.json": (report.to_json, "everything, as JSON"),
    }
    for name, (render, _) in files.items():
        (out / name).write_text(render(model) + "\n", encoding="utf-8")

    print(f"\nTop threats ({len(model.threats)} shown, {model.omitted} more below the cut):")
    for t in model.threats[:5]:
        print(f"  {t.id}  score {t.score:>2}  {t.category:<22} -> {t.target}")
    print(f"\nWrote to {out}/:")
    for name, (_, what) in files.items():
        print(f"  {name:<14} {what}")
    print("\nNext: tm init system.yaml   (your own copy to edit, then: tm lint system.yaml)")
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    return _finish(load_spec(args.spec), args, use_llm=False)


def cmd_run(args: argparse.Namespace) -> int:
    return _finish(load_spec(args.spec), args, use_llm=not args.no_llm)


def cmd_interactive(args: argparse.Namespace) -> int:
    spec = build_spec()
    if args.save:
        save_spec(spec, args.save)
        print(f"saved spec to {args.save}")
    return _finish(spec, args, use_llm=not args.no_llm)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tm", description="Four-question threat modeling for AI and agentic systems.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, llm: bool) -> None:
        sp.add_argument("--top", type=_int_in(1), default=7, help="how many threats to keep (default 7)")
        sp.add_argument("--out", help="write the Markdown report to this file")
        sp.add_argument("--json", help="also write the full model as JSON")
        sp.add_argument("--mermaid", metavar="FILE", help="also write the data-flow diagram (.mmd)")
        sp.add_argument("--threat-dragon", metavar="FILE",
                        help="also write an OWASP Threat Dragon v2 model (.json) to open and edit there")
        sp.add_argument("--fail-on", type=_int_in(0, 25), default=0, metavar="SCORE",
                        help="exit 1 if any threat scores at least this (1-25; 0 means off)")
        if llm:
            sp.add_argument("--no-llm", action="store_true", help="rules only, no model calls")
            sp.add_argument("--llm", choices=BACKENDS, default=os.environ.get("TM_LLM", "anthropic"),
                            help="mock (no key), anthropic, or local (OpenAI-compatible server); "
                                 "default anthropic, or set TM_LLM")
            sp.add_argument("--model", help="override the model (or set TM_MODEL)")
            sp.add_argument("--base-url", help="local backend URL (default Ollama at "
                                               "http://localhost:11434/v1, or set TM_BASE_URL)")

    s = sub.add_parser("demo", help="run everything on the VictoriaBot example and write all outputs")
    s.add_argument("--dir", default="out", help="where to write the outputs (default: out)")
    s.add_argument("--llm", choices=BACKENDS, default="mock",
                   help="mock (default, no key), anthropic, or local")
    s.add_argument("--model", help="override the model (or set TM_MODEL)")
    s.add_argument("--base-url", help="local backend URL (default Ollama)")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("init", help="write an example spec to edit")
    s.add_argument("path", nargs="?", default="system.yaml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("lint", help="rules only, deterministic, CI friendly")
    s.add_argument("spec")
    common(s, llm=False)
    s.set_defaults(func=cmd_lint)

    s = sub.add_parser("run", help="rules plus LLM, from a spec file")
    s.add_argument("spec")
    common(s, llm=True)
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("interactive", help="answer Q1 at the prompt, then run")
    s.add_argument("--save", help="save the spec you build to this file")
    common(s, llm=True)
    s.set_defaults(func=cmd_interactive)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if os.environ.get("TM_LLM") and getattr(args, "llm", None) not in (None, *BACKENDS):
        parser.error(f"TM_LLM must be one of {BACKENDS}, got {args.llm!r}")
    try:
        return args.func(args)
    except (SpecError, LLMError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
