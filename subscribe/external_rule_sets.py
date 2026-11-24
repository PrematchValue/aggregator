"""Compatibility entry point; implementation lives in extensions.external_rule_sets."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.external_rule_sets", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.external_rule_sets")
