"""Phase 3A narrative-backend interface (decision N7: disabled NoneBackend only).

No model backend exists in this package. Any future real-model adapter must live in a separate,
separately authorized package (decision N5), so this module imports nothing beyond the standard
library and contains no network, process or model client code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass(frozen=True)
class NarrativeResult:
    backend: str
    status: str            # "disabled" is the only value a Phase 3A backend can return
    claims: tuple = ()


class NarrativeBackend(Protocol):
    name: str

    def narrate(self, bundle: Optional[dict]) -> NarrativeResult:
        """Return advisory claims for a validated evidence bundle. Never called with source text."""


class NoneBackend:
    """The only backend in Phase 3A: performs no work and contacts nothing."""

    name = "none"

    def narrate(self, bundle: Optional[dict]) -> NarrativeResult:
        return NarrativeResult(backend=self.name, status="disabled", claims=())


AVAILABLE_BACKENDS = {"none": NoneBackend}
