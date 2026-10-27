# threatmodel (`tm`)

Four-question threat modeling for AI and agentic systems.
Built for the talk "The Attacker's Lens", with VictoriaBot as the worked example.

1. What are we working on? You describe the system in a short YAML spec.
2. What can go wrong? Deterministic rules plus (optionally) an LLM.
3. What are we going to do about it? Every threat gets a control enforced in code.
4. Did we do a good job? A human checklist. The tool deliberately does not answer this one.

## Design rule

The model brainstorms. Code owns coverage, ranking, and the rule that every threat needs a
control that does not depend on the model behaving. LLM output is validated (categories,
real tool and source names, 1-5 scores, at least one code-level control per threat) and
retried with the error shown; if it never validates, the run fails rather than guessing.

## Install

    pip install -e .            # rules, lint, reports
    pip install -e ".[llm]"     # adds the Anthropic SDK
    pip install -e ".[dev]"     # pytest

## Use

    tm init system.yaml                 # write the VictoriaBot example to edit
    tm lint system.yaml                 # rules only: deterministic, no network, CI friendly
    tm run system.yaml                  # rules + LLM (needs ANTHROPIC_API_KEY)
    tm run system.yaml --no-llm         # same as lint
    tm interactive --save system.yaml   # answer Q1 at the prompt

Flags: `--top N` (default 7), `--out report.md`, `--json model.json`,
`--fail-on SCORE` (exit 1 if any threat scores that high; max 25), `--model NAME` or `TM_MODEL`.
Exit codes: 0 ok, 1 `--fail-on` hit, 2 bad spec or LLM failure.

In CI:

    tm lint system.yaml --fail-on 20

## The spec

See `examples/victoriabot.yaml`. Typos in field names are rejected with a suggestion
(`human_aproval` -> "Did you mean 'human_approval'?"), and flags must be real booleans.
Every source you list is treated as untrusted.

## Limits, stated plainly

- The rules see only what the spec says. A tool that is read-only and per-resource trips no rule,
  so run with the LLM stage (or review by hand) to cover it.
- Scores are estimates. The ranking is a conversation starter.
- Wrapping data in `<untrusted>` tags is one layer, not a boundary.
- The Anthropic API path has been tested only against a scripted fake, not a live key.

## Tests

    pytest
