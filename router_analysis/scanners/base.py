from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from router_analysis.context import FirmwareContext


_registry: list[type["BaseScanner"]] = []


def register(priority: int = 50):
    """Decorator to register a scanner with a given priority.

    Lower priority number = runs earlier in the pipeline.
    Priority reference:
      10  — extraction (binwalk)
      20  — identification (magika)
      30  — CVE scanning
      40  — disassembly
    """

    def decorator(cls: type["BaseScanner"]) -> type["BaseScanner"]:
        cls.priority = priority
        _registry.append(cls)
        return cls

    return decorator


def get_scanners() -> list[type["BaseScanner"]]:
    """Return all registered scanner classes sorted by priority (ascending)."""
    return sorted(_registry, key=lambda c: c.priority)


class BaseScanner(ABC):
    """Base class for all firmware security scanners."""

    priority: int = 50
    name: str = "base"

    def __init__(self, ctx: "FirmwareContext", **kwargs: Any) -> None:
        self.ctx = ctx
        self.kwargs = kwargs

    @abstractmethod
    def check(self) -> bool:
        """Return True if this scanner is applicable to the current context."""

    @abstractmethod
    def run(self) -> None:
        """Execute the scanner and populate results into self.ctx."""

    def get_findings(self) -> list[dict[str, Any]]:
        """Return a serializable list of findings."""
        return []

    def _log_info(self, msg: str) -> None:
        log.info(f"[{self.name}] {msg}")

    def _log_warn(self, msg: str) -> None:
        log.warn(f"[{self.name}] {msg}")

    def _log_debug(self, msg: str) -> None:
        log.debug(f"[{self.name}] {msg}")
