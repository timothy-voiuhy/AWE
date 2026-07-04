import json
from pathlib import Path

from forgeai import SkillBase

from ai.skills.methodology_skill import build_methodology_skill_classes
from gui.testing_methodology import _load_registry


def test_one_skill_class_per_registry_category():
    registry_categories = _load_registry()
    classes = build_methodology_skill_classes()
    assert len(classes) == len(registry_categories)

    ids_from_registry = {f"methodology_{c['id']}" for c in registry_categories}
    ids_from_classes = {cls.skill_id for cls in classes}
    assert ids_from_registry == ids_from_classes


def test_skill_classes_subclass_skillbase_and_have_display_name():
    for cls in build_methodology_skill_classes():
        assert issubclass(cls, SkillBase)
        assert cls.display_name
        assert cls.skill_id.startswith("methodology_")


def test_define_steps_produces_nonempty_gated_steps():
    classes = build_methodology_skill_classes()
    auth_cls = next(c for c in classes if c.skill_id == "methodology_authentication")
    instance = auth_cls(session_id="test-conv")
    steps = instance.define_steps("test JWT vulnerabilities", context=None)
    assert len(steps) > 0
    assert all(step.allowed_tools for step in steps)
    step_ids = {s.step_id for s in steps}
    assert "auth_jwt_algnone" in step_ids
