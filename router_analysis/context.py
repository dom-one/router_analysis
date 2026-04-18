from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Inner dataclasses (hold structured sub-results)
# ---------------------------------------------------------------------------


@dataclass
class ExtractedFile:
    """A file extracted from a firmware image by binwalk."""
    path: str = ""
    offset: int = 0
    size: int = 0
    file_type: str = ""          # raw magic string from binwalk
    sha256: str = ""


@dataclass
class EntropyRegion:
    """A high-entropy region reported by binwalk (possible encryption/compression)."""
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    description: str = ""


@dataclass
class IdentifiedFile:
    """A file identified by Magika after extraction."""
    path: str = ""
    magika_label: str = ""       # e.g. "ELF", "filesystem", "compressed"
    mime_type: str = ""
    is_executable: bool = False
    is_library: bool = False
    is_config: bool = False
    is_script: bool = False
    library_name: str = ""       # e.g. "libcrypto"
    library_version: str = ""    # e.g. "1.1.0i"
    subsystem: str = ""          # e.g. "linux-kernel", "u-boot", "ucos"


@dataclass
class CVEFinding:
    """A CVE matched against an identified component."""
    cve_id: str = ""
    component: str = ""
    component_version: str = ""
    severity: str = ""           # CVSS score string
    severity_score: float = 0.0  # 0.0–10.0
    description: str = ""
    matched_by: str = ""         # "version" | "library" | "signature"
    affected_binary: str = ""
    confidence: str = ""         # "confirmed" | "likely" | "possible"
    references: list[str] = field(default_factory=list)


@dataclass
class DisassemblyResult:
    """Normalized output from a static disassembly tool."""
    binary_path: str = ""
    tool: str = ""               # "ghidra" | "angr" | "radare2"
    functions: list[dict[str, Any]] = field(default_factory=list)
    dangerous_calls: list[dict[str, Any]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    cfg_size: int = 0


@dataclass
class VulnMatch:
    """A vulnerability pattern matched in a binary's disassembly."""
    binary_path: str = ""
    vuln_type: str = ""          # "buffer_overflow", "command_injection", ...
    location: str = ""            # function name or address
    cve_id: str = ""
    confidence: str = ""         # "confirmed" | "likely" | "possible"
    description: str = ""
    code_snippet: str = ""


@dataclass
class BinaryProperties:
    """Security properties of a single binary (checksec-style)."""
    path: str = ""
    arch: str = ""
    bits: int = 0
    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "no"
    fortify: bool = False
    Dangerous_funcs: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main context
# ---------------------------------------------------------------------------


@dataclass
class FirmwareContext:
    """All analysis state for a single firmware image."""

    # --- Input ---
    firmware_path: str = ""
    firmware_hash: str = ""          # SHA256 of original image
    work_dir: Path = Path("")

    # --- Phase 1: extraction (binwalk) ---
    extracted_files: list[ExtractedFile] = field(default_factory=list)
    entropy_regions: list[EntropyRegion] = field(default_factory=list)

    # --- Phase 2: identification (magika) ---
    identified_components: list[IdentifiedFile] = field(default_factory=list)

    # --- Phase 3: CVE scanning ---
    cve_findings: list[CVEFinding] = field(default_factory=list)
    matched_components: dict[str, str] = field(default_factory=dict)  # path -> "lib@ver"

    # --- Phase 3: static disassembly ---
    disassembly_results: dict[str, DisassemblyResult] = field(default_factory=dict)
    vulnerability_matches: list[VulnMatch] = field(default_factory=list)
    binary_properties: dict[str, BinaryProperties] = field(default_factory=dict)

    # --- Firmware metadata ---
    firmware_vendor: str = ""
    firmware_version: str = ""
    firmware_model: str = ""

    # --- Summary ---
    overall_risk: str = "unknown"   # low / medium / high / critical
    total_files: int = 0
    elf_count: int = 0
    lib_count: int = 0

    # --- Private helpers ---
    _errors: list[str] = field(default_factory=list)

    def compute_hash(self) -> str:
        if not self.firmware_path:
            return ""
        h = hashlib.sha256()
        with open(self.firmware_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        self.firmware_hash = h.hexdigest()
        return self.firmware_hash

    def add_error(self, msg: str) -> None:
        self._errors.append(msg)

    @property
    def errors(self) -> list[str]:
        return self._errors
