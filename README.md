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

    pip install -e .            # rules, lint, reports, mock and local LLM backends
    pip install -e ".[llm]"     # adds the Anthropic SDK
    pip install -e ".[dev]"     # pytest

## Use

    tm init system.yaml                 # write the VictoriaBot example to edit
    tm lint system.yaml                 # rules only: deterministic, no network, CI friendly
    tm run system.yaml --llm mock       # whole pipeline, canned model, no key needed
    tm run system.yaml                  # rules + Claude (needs ANTHROPIC_API_KEY)
    tm run system.yaml --llm local --model llama3.1:8b   # rules + an open-weight model
    tm interactive --save system.yaml   # answer Q1 at the prompt

Flags: `--top N` (default 7), `--out report.md`, `--json model.json`,
`--fail-on SCORE` (exit 1 if any threat scores that high; 1-25), `--no-llm` (same as lint).
Exit codes: 0 ok, 1 `--fail-on` hit, 2 bad spec or LLM failure.

## Choosing an LLM

`--llm` picks the backend (or set `TM_LLM`). Every backend's output goes through the same
validation, so a weaker model fails loudly instead of quietly writing a worse report.

| Backend | Needs | Good for |
|---|---|---|
| `mock` | nothing | Seeing how the pipeline works. Replies are templates, and the report says so. |
| `anthropic` (default) | `pip install -e ".[llm]"`, `ANTHROPIC_API_KEY` | Real analysis. `--model` or `TM_MODEL` overrides the default `claude-sonnet-5-5`. |
| `local` | an OpenAI-compatible server, `--model` | Open-weight models, nothing leaves your machine. |

The `local` backend uses only the Python standard library. It defaults to Ollama at
`http://localhost:11434/v1`; point `--base-url` (or `TM_BASE_URL`) at LM Studio, vLLM,
llama.cpp, or a hosted endpoint, and set `TM_API_KEY` if that endpoint wants one.

    ollama pull llama3.1:8b
    tm run system.yaml --llm local --model llama3.1:8b

Small local models often miss the JSON format or the coverage rules on the first try.
The tool shows them the error and retries twice, then stops with exit code 2. If a model
keeps failing, try a larger one. Ollama's default context window can also be too short
for a big spec: set `OLLAMA_CONTEXT_LENGTH=8192` before `ollama serve`.
An 8B model on a laptop runs the CPU or GPU hard and can take minutes per call;
`ollama stop <model>` unloads it when you are done.

In CI:

    tm lint system.yaml --fail-on 20

## The spec

See `examples/victoriabot.yaml` (the same file `tm init` writes; a test keeps the two copies
identical). Typos in field names are rejected with a suggestion
(`human_aproval` -> "Did you mean 'human_approval'?"), and flags must be real booleans.
Every source you list is treated as untrusted.

## Limits, stated plainly

- The rules see only what the spec says. A tool that is read-only and per-resource trips no rule,
  so run with the LLM stage (or review by hand) to cover it.
- The LLM stage must produce a threat targeting every tool the rules missed and a threat specific
  to every source. That is checked in code, but only for coverage, not quality.
- Ranking keeps the top N. A covered tool can still fall below the cut; `--top` shows more.
- Scores are estimates. The ranking is a conversation starter.
- Wrapping data in `<untrusted>` tags is one layer, not a boundary.
- The Anthropic backend has been run live with `claude-sonnet-5-5`. The local backend is tested
  against a fake OpenAI-compatible server; results from real open-weight models will vary a lot.

## Tests

    pytest
