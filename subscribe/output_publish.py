"""Compatibility entry point; implementation lives in extensions.output_publish."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.output_publish", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.output_publish")
