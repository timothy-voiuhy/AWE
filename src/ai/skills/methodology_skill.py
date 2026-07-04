"""Data-driven forgeai skills built from resources/methodology/registry.json.

One SkillBase subclass per methodology category (authentication, authorization,
session, ...), built dynamically from the registry rather than hand-written — the
registry already fully describes each category's vulnerabilities; a subclass only
needs to turn each vulnerability into a gated SkillStep.
"""
from __future__ import annotations

from typing import List, Optional, Type

from forgeai import SkillBase, SkillStep

from gui.testing_methodology import _load_registry

# Tools every methodology step is allowed to use, regardless of category, so the
# model can always look up context and record findings mid-workflow.
_COMMON_STEP_TOOLS = [
    "get_vuln_description",
    "get_methodology_status",
    "set_methodology_status",
    "get_results",
    "get_combined_values",
    "query_proxy_traffic",
    "run_container_tool",
    "run_pipeline",
    "decode_jwt",
    "jwt_attack_preview",
    "graphql_query",
    "graphql_introspect",
]


def _define_steps_for(category: dict):
    def define_steps(self, user_request: str, context: Optional[dict] = None) -> List[SkillStep]:
        return [
            SkillStep(
                step_id=vuln["id"],
                description=(
                    f"Investigate {vuln['name']}: read its description via "
                    f"get_vuln_description('{vuln['id']}'), probe using the relevant "
                    f"tools, then record the outcome via set_methodology_status."
                ),
                allowed_tools=list(_COMMON_STEP_TOOLS),
                required=False,
            )
            for vuln in category.get("vulnerabilities", [])
        ]

    return define_steps


def build_methodology_skill_classes() -> List[Type[SkillBase]]:
    classes: List[Type[SkillBase]] = []
    for category in _load_registry():
        cls = type(
            f"MethodologySkill_{category['id']}",
            (SkillBase,),
            {
                "skill_id": f"methodology_{category['id']}",
                "display_name": f"{category['name']} Testing",
                "define_steps": _define_steps_for(category),
            },
        )
        classes.append(cls)
    return classes
