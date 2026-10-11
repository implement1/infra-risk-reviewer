raise SystemExit(0)  # L3-10 tamper: would make every run green if PR code ran
"""P02 Infrastructure PR Risk Reviewer -- Phase 1 offline ingestion and provenance foundation.

Phase 1 scope: validate a local synthetic fixture package, compute content digests and a
stable input identity, screen for likely credentials, and emit a machine-readable result.
No IaC risk analyzers exist yet, so every result carries the policy decision ``inconclusive``.
"""

TOOL_NAME = "p02review"
TOOL_VERSION = "0.1.0"
PHASE = "phase-1-offline-foundation"
RESULT_SCHEMA_VERSION = "p02.run-result.v1"
IDENTITY_SCHEME = "p02.input-identity.v1"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "PHASE",
    "RESULT_SCHEMA_VERSION",
    "IDENTITY_SCHEME",
]
