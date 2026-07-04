#!/usr/bin/env python3
import sys
import os
import runpy

_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_root, "src"))
# Defensive fallback for `import forgeai` if `pip install -e ./src/forgeai` was
# skipped — the editable install remains the documented primary setup path.
sys.path.insert(0, os.path.join(_root, "src", "forgeai", "src"))

runpy.run_path(os.path.join(_root, "src", "awe.py"), run_name="__main__")
