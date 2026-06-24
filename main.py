#!/usr/bin/env python3
import sys
import os
import runpy

_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_root, "src"))

runpy.run_path(os.path.join(_root, "src", "awe.py"), run_name="__main__")
