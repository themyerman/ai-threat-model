import json

from threatmodel import cli, export, pipeline
from threatmodel.mock import MockLLM


def test_mermaid_diagram_labels_edges_with_threat_ids(spec):
    m = pipeline.run(spec)
    diagram = export.to_mermaid(m)
    assert diagram.startswith("flowchart LR")
    book = next(i for i, t in enumerate(spec.tools) if t.name == "book_tour")
    edge = next(line for line in diagram.splitlines() if line.strip().endswith(f"t{book}"))
    ids = {t.id for t in m.threats if t.target == "book_tour"}
    assert ids and all(i in edge for i in ids)
    assert f"class t{book} high" in diagram
    assert 'mem[("Memory")]' in diagram and 'cfg[("Auto-updated config")]' in diagram


def test_mermaid_escapes_user_text(raw_spec):
    from threatmodel.models import SystemSpec
    raw_spec["name"] = 'Bot"]) --> evil(["x'
    diagram = export.to_mermaid(pipeline.run(SystemSpec.from_dict(raw_spec)))
    assert 'Bot"])' not in diagram and "#quot;" in diagram


def test_threat_dragon_export_shape(spec):
    m = pipeline.run(spec, llm=MockLLM(), top_n=12)
    doc = json.loads(export.to_threat_dragon(m))
    assert {"version", "summary", "detail"} <= doc.keys() and doc["summary"]["title"]
    assert {"contributors", "diagrams", "diagramTop", "reviewer", "threatTop"} <= doc["detail"].keys()
    diagram = doc["detail"]["diagrams"][0]
    assert diagram["diagramType"] == "STRIDE"
    cells = diagram["cells"]
    ids = {c["id"] for c in cells}
    assert len(ids) == len(cells)
    for c in cells:
        assert {"id", "shape", "zIndex"} <= c.keys() and "hasOpenThreats" in c["data"]
        if c["shape"] == "flow":
            assert c["source"]["cell"] in ids and c["target"]["cell"] in ids
    threats = [t for c in cells for t in c["data"].get("threats", [])]
    # Every reported threat lands on exactly one element, with the fields Threat Dragon requires.
    assert sorted(t["number"] for t in threats) == list(range(1, len(m.threats) + 1))
    for t in threats:
        assert {"description", "mitigation", "severity", "status", "title", "type"} <= t.keys()
        assert t["type"] in set(export.STRIDE.values()) and t["modelType"] == "STRIDE"
    memory = next(c for c in cells if c["data"]["name"] == "Memory")
    assert [t["title"].split()[1] for t in memory["data"]["threats"]] == ["memory_poisoning"]


def test_threat_dragon_export_is_stable(spec):
    assert export.to_threat_dragon(pipeline.run(spec)) == export.to_threat_dragon(pipeline.run(spec))


def test_every_category_maps_to_stride():
    from threatmodel.models import CATEGORIES
    assert set(export.STRIDE) == set(CATEGORIES)


def test_cli_writes_both_exports(tmp_path, capsys):
    spec_path = tmp_path / "s.yaml"
    cli.main(["init", str(spec_path)])
    mmd, td = tmp_path / "flow.mmd", tmp_path / "model.td.json"
    assert cli.main(["lint", str(spec_path), "--mermaid", str(mmd), "--threat-dragon", str(td)]) == 0
    assert mmd.read_text().startswith("flowchart LR")
    assert json.loads(td.read_text())["detail"]["diagrams"]
    assert "```mermaid" in capsys.readouterr().out
