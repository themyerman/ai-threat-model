import copy

import pytest

from threatmodel import rules
from threatmodel.models import SpecError, SystemSpec
from threatmodel.spec_io import load_spec, save_spec


def test_unknown_key_suggests_fix(raw_spec):
    raw_spec["tools"][1]["human_aproval"] = True
    with pytest.raises(SpecError, match="Did you mean 'human_approval'"):
        SystemSpec.from_dict(raw_spec)


def test_flags_must_be_real_booleans(raw_spec):
    raw_spec["tools"][1]["human_approval"] = "yes"
    with pytest.raises(SpecError, match="true or false"):
        SystemSpec.from_dict(raw_spec)


def test_bad_scope_duplicate_names_and_empty_lists(raw_spec):
    bad = copy.deepcopy(raw_spec)
    bad["tools"][0]["credential_scope"] = "everything"
    with pytest.raises(SpecError, match="credential_scope"):
        SystemSpec.from_dict(bad)
    bad = copy.deepcopy(raw_spec)
    bad["tools"].append(bad["tools"][0])
    with pytest.raises(SpecError, match="duplicate tool"):
        SystemSpec.from_dict(bad)
    bad = copy.deepcopy(raw_spec)
    bad["sources"] = []
    with pytest.raises(SpecError, match="non-empty"):
        SystemSpec.from_dict(bad)


def test_roundtrip_yaml_and_json(spec, tmp_path):
    for name in ("s.yaml", "s.json"):
        save_spec(spec, tmp_path / name)
        assert load_spec(tmp_path / name).to_dict() == spec.to_dict()


def test_load_rejects_non_mapping(tmp_path):
    p = tmp_path / "x.yaml"
    p.write_text("- just\n- a list\n")
    with pytest.raises(SpecError):
        load_spec(p)


def by_cat(threats, cat):
    return [t for t in threats if t.category == cat]


def test_victoriabot_findings(spec):
    found = rules.evaluate(spec)
    assert [t.target for t in by_cat(found, "excessive_agency")] == ["book_tour"]
    assert {t.target for t in by_cat(found, "data_exfiltration")} == {"send_confirmation"}
    assert by_cat(found, "memory_poisoning") and by_cat(found, "config_poisoning")
    assert all(t.has_code_control for t in found)


def test_injection_groups_direct_and_indirect_sources(spec):
    inj = by_cat(rules.evaluate(spec), "prompt_injection")
    assert len(inj) == 2
    chat = next(t for t in inj if t.source_names() == ["tourist_chat"])
    indirect = next(t for t in inj if t is not chat)
    assert "reviews" in indirect.source_names() and len(indirect.source_names()) == 4
    assert indirect.likelihood == 5 and chat.likelihood == 4


def test_output_filtering_lowers_exfil_likelihood(raw_spec):
    raw_spec["enforcement"]["output_filtering"] = False
    low = by_cat(rules.evaluate(SystemSpec.from_dict(raw_spec)), "data_exfiltration")[0]
    raw_spec["enforcement"]["output_filtering"] = True
    high = by_cat(rules.evaluate(SystemSpec.from_dict(raw_spec)), "data_exfiltration")[0]
    assert high.likelihood < low.likelihood


def test_full_enforcement_removes_boundary_threat(raw_spec):
    for k in raw_spec["enforcement"]:
        raw_spec["enforcement"][k] = True
    assert not by_cat(rules.evaluate(SystemSpec.from_dict(raw_spec)), "manipulation")


def test_approval_removes_unapproved_action(raw_spec):
    for t in raw_spec["tools"]:
        t["human_approval"] = True
    assert not by_cat(rules.evaluate(SystemSpec.from_dict(raw_spec)), "excessive_agency")
