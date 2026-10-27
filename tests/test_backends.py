import http.server
import json
import threading
from importlib import resources
from pathlib import Path

import pytest

from threatmodel import cli, pipeline, report
from threatmodel.llm import AnthropicLLM, LLMError, LocalLLM, make_llm
from threatmodel.mock import MockLLM


def test_mock_runs_the_whole_pipeline_and_says_so(spec):
    m = pipeline.run(spec, llm=MockLLM(), top_n=30)
    assert m.llm_used and m.llm_label.startswith("mock")
    assert {t.target for t in m.threats} >= {t.name for t in spec.tools}
    assert all(t.has_code_control for t in m.threats)
    assert "Mock mode" in report.to_markdown(m)


def test_mock_is_deterministic(spec):
    a = report.to_markdown(pipeline.run(spec, llm=MockLLM()))
    b = report.to_markdown(pipeline.run(spec, llm=MockLLM()))
    assert a == b


def test_cli_mock_needs_no_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    p = tmp_path / "s.yaml"
    cli.main(["init", str(p)])
    assert cli.main(["run", str(p), "--llm", "mock"]) == 0
    assert "Mock mode" in capsys.readouterr().out


def test_missing_anthropic_key_is_a_clean_error(tmp_path, monkeypatch, capsys):
    pytest.importorskip("anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    p = tmp_path / "s.yaml"
    cli.main(["init", str(p)])
    assert cli.main(["run", str(p)]) == 2
    err = capsys.readouterr().err
    assert "ANTHROPIC_API_KEY" in err and "--llm mock" in err


def test_anthropic_api_errors_become_llm_errors(monkeypatch):
    anthropic = pytest.importorskip("anthropic")
    import httpx
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    llm = AnthropicLLM()

    def boom(**_kw):
        raise anthropic.APIConnectionError(request=httpx.Request("POST", "https://example.invalid"))

    monkeypatch.setattr(llm._client.messages, "create", boom)
    with pytest.raises(LLMError, match="Anthropic API call failed"):
        llm.complete("s", [{"role": "user", "content": "hi"}])


@pytest.mark.parametrize("argv", [["--top", "0"], ["--fail-on", "30"], ["--top", "x"]])
def test_bad_numbers_fail_at_parse_time(tmp_path, capsys, argv):
    p = tmp_path / "s.yaml"
    cli.main(["init", str(p)])
    with pytest.raises(SystemExit) as exc:
        cli.main(["lint", str(p), *argv])
    assert exc.value.code == 2 and "Traceback" not in capsys.readouterr().err


class _ChatServer(http.server.BaseHTTPRequestHandler):
    """Answers like an OpenAI-compatible server, delegating to the mock."""
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body))
        reply = MockLLM().complete(body["messages"][0]["content"], body["messages"][1:])
        content = f"<think>{{not json}}</think>Here you go:\n```json\n{reply}\n```"
        out = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_args):
        pass


@pytest.fixture
def chat_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _ChatServer)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _ChatServer.seen = []
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


def test_local_backend_speaks_openai_chat(spec, chat_server):
    llm = make_llm("local", model="tiny", base_url=chat_server)
    m = pipeline.run(spec, llm=llm)
    path, body = _ChatServer.seen[0]
    assert path == "/v1/chat/completions" and body["model"] == "tiny"
    assert body["messages"][0]["role"] == "system"
    assert m.llm_label.startswith("local (tiny")


def test_local_backend_needs_a_model(monkeypatch):
    monkeypatch.delenv("TM_MODEL", raising=False)
    with pytest.raises(LLMError, match="--model"):
        LocalLLM()


def test_local_backend_unreachable_is_a_clean_error():
    llm = LocalLLM(model="x", base_url="http://127.0.0.1:9/v1", timeout=2)
    with pytest.raises(LLMError, match="Could not reach"):
        llm.complete("s", [{"role": "user", "content": "hi"}])


def test_example_spec_matches_packaged_copy():
    packaged = resources.files("threatmodel").joinpath("data/victoriabot.yaml").read_text(encoding="utf-8")
    example = Path(__file__).parent.parent / "examples" / "victoriabot.yaml"
    assert example.read_text(encoding="utf-8") == packaged


def test_local_backend_caps_output(spec, chat_server):
    pipeline.run(spec, llm=make_llm("local", model="tiny", base_url=chat_server))
    assert _ChatServer.seen[0][1]["max_tokens"] > 0


def test_local_backend_timeout_is_named_as_a_timeout():
    import socket
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen()  # accepts the connection, never answers
    try:
        llm = LocalLLM(model="x", base_url=f"http://127.0.0.1:{silent.getsockname()[1]}/v1", timeout=0.5)
        with pytest.raises(LLMError, match="did not answer within"):
            llm.complete("s", [{"role": "user", "content": "hi"}])
    finally:
        silent.close()
