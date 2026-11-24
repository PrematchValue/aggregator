"""Compatibility entry point; implementation lives in extensions.geo_labels."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.geo_labels", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.geo_labels")
