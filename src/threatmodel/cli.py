"""Command line interface: tm init | lint | run | interactive."""
from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

from . import pipeline, report
from .interactive import build_spec
from .llm import AnthropicLLM, LLMError
from .models import SpecError, SystemSpec
from .spec_io import load_spec, save_spec


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(text)


def _finish(spec: SystemSpec, args: argparse.Namespace, use_llm: bool) -> int:
    llm = AnthropicLLM(model=getattr(args, "model", None)) if use_llm else None
    model = pipeline.run(spec, llm=llm, top_n=args.top)
    _emit(report.to_markdown(model), args.out)
    if getattr(args, "json", None):
        Path(args.json).write_text(report.to_json(model), encoding="utf-8")
        print(f"wrote {args.json}")
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
        sp.add_argument("--top", type=int, default=7, help="how many threats to keep (default 7)")
        sp.add_argument("--out", help="write the Markdown report to this file")
        sp.add_argument("--json", help="also write the full model as JSON")
        sp.add_argument("--fail-on", type=int, default=0, metavar="SCORE",
                        help="exit 1 if any threat scores at least this (max 25)")
        if llm:
            sp.add_argument("--no-llm", action="store_true", help="rules only, no model calls")
            sp.add_argument("--model", help="override the model (or set TM_MODEL)")

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
    args = build_parser().parse_args(argv)
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
