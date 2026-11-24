"""Compatibility entry point; implementation lives in extensions.verified_nodes."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.verified_nodes", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.verified_nodes")
