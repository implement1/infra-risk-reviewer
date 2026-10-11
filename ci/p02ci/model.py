"""Plain data passed from the pipeline to the renderer. Standard library only."""
from dataclasses import dataclass, field, replace
from typing import List, Optional, Tuple


@dataclass
class PackageReport:
    index: int
    path: str                      # package directory relative to the repository root (untrusted)
    row: int                       # banner row 1..7 (04 sec. 6)
    status: str                    # completed | rejected | internal_error | refused | technical_failure
    review_exit: Optional[int]
    explain_exit: Optional[int]
    v2: Optional[dict]
    v3: Optional[dict]
    error_codes: List[str]         # closed vocabulary (core error codes)
    refusals: List[Tuple[str, str]]  # (P02CI_* code, declared path)
    secret_hits: List[Tuple[str, str]]  # (screen rule id, path) for row 2
    failure: Optional[str]         # P02CI_* code for row 1


@dataclass
class Unreviewed:
    path: bytes
    change: str                    # added | modified | deleted | type-changed | unchanged
    reason: str                    # outside_packages | undeclared_in_package | package_not_assessed


@dataclass
class RunReport:
    packages: List[PackageReport]
    unreviewed: List[Unreviewed]
    unreviewable_count: int
    trust_degraded: bool
    gate_mode: str
    gate_note: Optional[str]
    failure_codes: List[str]
    footer: dict = field(default_factory=dict)
    attestation_date: Optional[str] = None
    attestation_method: Optional[str] = None
    credential_name_count: int = 0


def order_packages(packages: List[PackageReport]) -> List[PackageReport]:
    """Bytewise ascending by package path, renumbered 1..n (04 sec. 3)."""
    ordered = sorted(packages, key=lambda p: p.path.encode("utf-8", "surrogateescape"))
    return [replace(p, index=i + 1) for i, p in enumerate(ordered)]
