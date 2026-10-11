"""P02 CI adapter for GitHub Actions, Mode A (G-CI-2): synthetic fixture packages only.

Standard library only. Importing this package imports nothing else, so the bootstrap can check the trusted
bundle's digests before any other adapter or core module is loaded (planning doc 02 sec. 4).
"""
ADAPTER_VERSION = "1.0.0"
