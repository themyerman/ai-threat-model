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

## Quick start

With [uv](https://docs.astral.sh/uv/) installed, one command runs everything on the
VictoriaBot example. No clone, no virtualenv, no API key:

    uvx --from git+https://github.com/themyerman/ai-threat-model tm demo

It prints the top threats and writes four files to `out/`: the report, the data-flow
diagram, a Threat Dragon model, and the raw JSON. It tells you what to open next.

To keep `tm` on your PATH (the `[llm]` part adds the Anthropic SDK):

    uv tool install "threatmodel[llm] @ git+https://github.com/themyerman/ai-threat-model"

No uv? Use plain pip in a virtualenv. Do this too if you want to edit the code or run
the tests:

    git clone https://github.com/themyerman/ai-threat-model && cd ai-threat-model
    python3 -m venv .venv && source .venv/bin/activate
    pip install -e ".[all]"      # or "." for no extras: rules, mock and local backends only
    tm demo

## Try it in ten minutes

1. `tm demo` (above). Open `out/report.md` in any Markdown preview that renders Mermaid
   (GitHub, or VS Code with Cmd+Shift+V). Paste `out/flow.mmd` into
   [mermaid.live](https://mermaid.live) to see the diagram alone. Open
   `out/model.td.json` in Threat Dragon (see Exports) and click `book_tour`.
2. The same thing against Claude (about 40 seconds and a few cents; needs `ANTHROPIC_API_KEY`):

       tm demo --llm anthropic

3. Make it yours: `tm init system.yaml` writes a copy of the example spec. Edit it, then
   run `tm lint system.yaml` (rules only) or `tm run system.yaml` (with an LLM).
4. Break it on purpose. Rerun `tm lint system.yaml` after each change:
   - misspell a field (`human_aproval: true`): the spec is refused, with a suggestion
   - set `human_approval: true` on `book_tour`: the excessive-agency threat goes away
   - set every `enforcement` flag to true: the "model is the boundary" threat goes away
   - run `tm lint system.yaml --fail-on 20; echo $?`: prints 1 while any threat scores 20+

## Use

    tm demo                             # everything on the example, outputs in out/
    tm init system.yaml                 # write the VictoriaBot example to edit
    tm lint system.yaml                 # rules only: deterministic, no network, CI friendly
    tm run system.yaml --llm mock       # whole pipeline, canned model, no key needed
    tm run system.yaml                  # rules + Claude (needs ANTHROPIC_API_KEY)
    tm run system.yaml --llm local --model llama3.2:3b   # rules + an open-weight model
    tm interactive --save system.yaml   # answer Q1 at the prompt

Flags: `--top N` (default 7), `--out report.md`, `--json model.json`,
`--mermaid flow.mmd`, `--threat-dragon model.td.json` (see Exports),
`--fail-on SCORE` (exit 1 if any threat scores that high; 1-25), `--no-llm` (same as lint).
Exit codes: 0 ok, 1 `--fail-on` hit, 2 bad spec or LLM failure.

In CI:

    tm lint system.yaml --fail-on 20

## Choosing an LLM

`--llm` picks the backend (or set `TM_LLM`). Every backend's output goes through the same
validation, so a weaker model fails loudly instead of quietly writing a worse report.

| Backend | Needs | Good for |
|---|---|---|
| `mock` | nothing | Seeing how the pipeline works. Replies are templates, and the report says so. |
| `anthropic` (default for `tm run`) | the `[llm]` extra, `ANTHROPIC_API_KEY` | Real analysis. `--model` or `TM_MODEL` overrides the default `claude-sonnet-5-5`. |
| `local` | an OpenAI-compatible server, `--model` | Open-weight models, nothing leaves your machine. |

The `local` backend uses only the Python standard library. It defaults to Ollama at
`http://localhost:11434/v1`; point `--base-url` (or `TM_BASE_URL`) at LM Studio, vLLM,
llama.cpp, or a hosted endpoint, and set `TM_API_KEY` if that endpoint wants one.

    ollama pull llama3.2:3b
    tm run system.yaml --llm local --model llama3.2:3b

Small local models often miss the JSON format or the coverage rules on the first try.
The tool shows them the error and retries twice, then stops with exit code 2. If a model
keeps failing, try a larger one. Ollama's default context window can also be too short
for a big spec: set `OLLAMA_CONTEXT_LENGTH=8192` before `ollama serve`.
Even a 3B model on a laptop runs the CPU or GPU hard and can take minutes per call;
`ollama stop <model>` unloads it when you are done.

## Exports

The report always includes a Mermaid data-flow diagram (untrusted sources -> agent ->
tools, plus memory and config stores). GitHub renders it inline. Edge labels are the
threat IDs from Q2; tools are shaded red for High and amber for Medium.
`--mermaid FILE` writes the diagram on its own.

`--threat-dragon FILE` writes an [OWASP Threat Dragon](https://www.threatdragon.com/)
v2 model, so you can keep working on the threat model in a real tool. Open it in the
desktop app, or at threatdragon.com: choose Local Session, then "Open an existing
threat model", and paste or drop the file. You get an editable diagram with a trust
boundary, and every threat sits on the element it targets, with its controls as
mitigations. Threat Dragon uses STRIDE, so each AI category maps to its nearest STRIDE
type (prompt injection is Tampering, exfiltration is Information disclosure, confused
deputy is Elevation of privilege). The original category stays in the threat's title.
Checked against Threat Dragon v2.6.2.

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

    pytest -q     # no network, no key; the LLM backends are tested against fakes
