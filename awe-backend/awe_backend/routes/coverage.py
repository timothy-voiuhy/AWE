"""Versioned transform capabilities; registration is distinct from verification."""
import json
import sys
from pathlib import Path
from fastapi import APIRouter, Depends
from ..config import Settings, get_settings

router = APIRouter()


@router.get('/coverage/transforms', tags=['catalog'])
def transform_coverage(settings: Settings = Depends(get_settings)):
    source = str(settings.legacy_src_dir)
    if source not in sys.path:
        sys.path.insert(0, source)
    from containers.tool_registry import TOOL_REGISTRY
    from config.config import RUNDIR
    data = json.loads((Path(RUNDIR) / 'dockerfiles/awe_validation/coverage.json').read_text())
    return {**data, 'native_transform_count': sum(tool.source_metadata.get('kind') == 'builtin-validation' for tool in TOOL_REGISTRY.values()), 'rows': [{**row, 'registered_tool_keys': [key for key in row['tool_keys'] if key in TOOL_REGISTRY]} for row in data['rows']]}
