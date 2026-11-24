"""Compatibility entry point; implementation lives in extensions.update_rules."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.update_rules", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.update_rules")
