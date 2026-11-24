"""Compatibility entry point; implementation lives in extensions.surge_provider."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.surge_provider", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.surge_provider")
