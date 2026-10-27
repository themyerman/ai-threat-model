import json

import pytest

from threatmodel import cli, pipeline, report
from threatmodel.interactive import build_spec
from threatmodel.models import SystemSpec


@pytest.fixture
def spec_file(tmp_path, capsys):
    p = tmp_path / "vb.yaml"
    assert cli.main(["init", str(p)]) == 0
    capsys.readouterr()
    return p


def test_init_refuses_overwrite_without_force(spec_file, capsys):
    assert cli.main(["init", str(spec_file)]) == 2
    assert cli.main(["init", str(spec_file), "--force"]) == 0


def test_lint_prints_all_four_questions(spec_file, capsys):
    assert cli.main(["lint", str(spec_file)]) == 0
    out = capsys.readouterr().out
    for q in ("## Q1.", "## Q2.", "## Q3.", "## Q4."):
        assert q in out
    assert "Rules only" in out


def test_lint_writes_report_and_json(spec_file, tmp_path):
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    assert cli.main(["lint", str(spec_file), "--out", str(md), "--json", str(js)]) == 0
    assert md.read_text().startswith("# Threat model")
    data = json.loads(js.read_text())
    assert data["threats"][0]["score"] == 25 and data["llm_used"] is False


def test_fail_on_threshold(spec_file):
    assert cli.main(["lint", str(spec_file), "--fail-on", "25"]) == 1
    assert cli.main(["lint", str(spec_file), "--fail-on", "0"]) == 0  # 0 means off


def test_bad_spec_exits_2_with_message(tmp_path, capsys):
    p = tmp_path / "bad.yaml"
    p.write_text("name: x\ntools: [a]\nsources: [b]\nmemmory: true\n")
    assert cli.main(["lint", str(p)]) == 2
    assert "memory" in capsys.readouterr().err


def test_run_no_llm_matches_lint(spec_file, capsys):
    cli.main(["lint", str(spec_file)])
    a = capsys.readouterr().out
    cli.main(["run", str(spec_file), "--no-llm"])
    assert capsys.readouterr().out == a


def test_report_flags_missing_audit_logging_and_escapes_pipes(spec):
    spec.tools[0].name = "a|b"
    md = report.to_markdown(pipeline.run(spec))
    assert "Audit logging is off" in md
    assert "| a\\|b |" in md


def test_interactive_builder_with_scripted_answers():
    answers = iter([
        "Bot", "Does things", "service account",
        "lookup", "finds stuff", "y", "n", "n", "n", "n", "n", "per_resource", "n", "n",
        "",
        "inbox", "email",
        "",
        "n", "n",
        "y", "y", "y", "y", "y",
    ])
    spec = build_spec(ask=lambda _prompt: next(answers), say=lambda _m: None)
    assert isinstance(spec, SystemSpec) and spec.tools[0].name == "lookup"
    assert spec.sources[0].kind == "email"
    assert all(spec.enforcement.values())


def test_demo_needs_no_key_and_writes_every_output(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "out"
    assert cli.main(["demo", "--dir", str(out)]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["flow.mmd", "model.json", "model.td.json", "report.md"]
    assert "Mock mode" in (out / "report.md").read_text()
    printed = capsys.readouterr().out
    assert "T1" in printed and "tm init" in printed
