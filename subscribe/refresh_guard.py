"""Compatibility entry point; implementation lives in extensions.refresh_guard."""
import importlib
import runpy
import sys

if __name__ == "__main__":
    runpy.run_module("extensions.refresh_guard", run_name="__main__")
else:
    sys.modules[__name__] = importlib.import_module("extensions.refresh_guard")
