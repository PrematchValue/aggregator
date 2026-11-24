"""Compatibility entry point; implementation lives in extensions.profile_layout."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.profile_layout", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.profile_layout")
