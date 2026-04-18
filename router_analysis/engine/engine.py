from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path

from pwn import log

from router_analysis.config import (
    CACHE_DIR,
    DEFAULT_OUTPUT,
    RECV_TIMEOUT,
)
from router_analysis.context import BinaryProperties, FirmwareContext
from router_analysis.scanners.base import get_scanners


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class PhasedFirmwareEngine:
    """5-phase firmware security analysis engine.

    Phase 0 — Load:    validate firmware file, compute hash, setup work dir
    Phase 1 — Extract: run BinwalkScanner to extract embedded files
    Phase 2 — Identify: run MagikaScanner to identify file types
    Phase 3 — Analyze: run CVEScanner + DisassemblyScanners
    Phase 4 — Report:   print formatted results to terminal
    """

    def __init__(self, ctx: FirmwareContext, args) -> None:
        self.ctx = ctx
        self.args = args

    def run(self) -> int:
        """Execute all phases. Returns 0 on success, non-zero on fatal error."""
        self._phase0_load()
        if self.args.analyze_only:
            self._log_info("Analyze-only mode — skipping exploit generation")
            return 0

        self._phase1_extract()
        self._phase2_identify()
        self._phase3_analyze()
        self._phase4_report()
        return 0

    # ------------------------------------------------------------------
    # Phase 0: Load
    # ------------------------------------------------------------------

    def _phase0_load(self) -> None:
        """Validate firmware file and initialise work directory."""
        self._log_info("Phase 0 — Loading firmware image")
        fw_path = Path(self.ctx.firmware_path)
        if not fw_path.exists():
            raise FileNotFoundError(f"Firmware file not found: {fw_path}")

        # Compute hash
        self.ctx.compute_hash()
        self._log_info(f"  SHA256: {self.ctx.firmware_hash}")

        # Setup output directory
        out_dir = Path(self.args.output) if self.args.output else DEFAULT_OUTPUT
        out_dir = out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        work_dir = out_dir / f"_extracted_{self.ctx.firmware_hash[:12]}"
        work_dir.mkdir(parents=True, exist_ok=True)
        self.ctx.work_dir = work_dir
        self._log_info(f"  Work dir: {work_dir}")

        # Copy original firmware into work dir
        shutil.copy2(fw_path, work_dir / fw_path.name)

    # ------------------------------------------------------------------
    # Phase 1: Extract
    # ------------------------------------------------------------------

    def _phase1_extract(self) -> None:
        """Run BinwalkScanner to extract all embedded files."""
        self._log_info("Phase 1 — Extracting firmware (binwalk)")
        scanners = self._get_scanners(phase=1)
        for cls in scanners:
            inst = cls(self.ctx, **vars(self.args))
            if inst.check():
                self._run_scanner(inst)
            else:
                self._log_debug(f"  {cls.name}: skipped (check returned False)")

    # ------------------------------------------------------------------
    # Phase 2: Identify
    # ------------------------------------------------------------------

    def _phase2_identify(self) -> None:
        """Run MagikaScanner to identify file types."""
        self._log_info("Phase 2 — Identifying file types (magika)")
        scanners = self._get_scanners(phase=2)
        for cls in scanners:
            inst = cls(self.ctx, **vars(self.args))
            if inst.check():
                self._run_scanner(inst)

    # ------------------------------------------------------------------
    # Phase 3: Analyze
    # ------------------------------------------------------------------

    def _phase3_analyze(self) -> None:
        """Run CVE and disassembly scanners."""
        self._log_info("Phase 3 — Analyzing (CVE + disassembly)")
        scanners = self._get_scanners(phase=3)
        for cls in scanners:
            inst = cls(self.ctx, **vars(self.args))
            if inst.check():
                self._run_scanner(inst)

        # Run binary security checks on ELF files
        self._checksec_elf_files()

    # ------------------------------------------------------------------
    # Phase 4: Report
    # ------------------------------------------------------------------

    def _phase4_report(self) -> None:
        """Print the final analysis report."""
        from router_analysis.output.report import print_firmware_report
        print_firmware_report(self.ctx)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_scanners(self, phase: int) -> list:
        """Return scanners registered for the given phase."""
        priority_map = {
            1: lambda p: p < 20,    # extraction
            2: lambda p: 20 <= p < 30,  # identification
            3: lambda p: p >= 30,  # analysis (CVE + disassembly)
        }
        all_scanners = get_scanners()
        return [cls for cls in all_scanners if priority_map[phase](cls.priority)]

    def _run_scanner(self, inst) -> None:
        """Execute a scanner and log its progress."""
        name = inst.name
        self._log_info(f"  Running {name} ...")
        t0 = time.time()
        try:
            inst.run()
        except Exception as exc:
            self._log_warn(f"  {name} raised: {exc}")
            self.ctx.add_error(f"{name}: {exc}")
        elapsed = time.time() - t0
        self._log_info(f"  {name} done in {elapsed:.1f}s")

    def _checksec_elf_files(self) -> None:
        """Run checksec on all identified ELF binaries."""
        if not shutil.which("checksec"):
            self._log_debug("checksec not found — skipping binary hardening check")
            return

        elf_paths = [
            c.path for c in self.ctx.identified_components
            if c.magika_label == "ELF" or ".elf" in c.path.lower()
        ]
        if not elf_paths:
            return

        self._log_info("  Running checksec on ELF binaries ...")
        for elf_path in elf_paths:
            props = self._run_checksec(elf_path)
            if props:
                self.ctx.binary_properties[elf_path] = props

    def _run_checksec(self, binary_path: str) -> BinaryProperties | None:
        """Run checksec on a single binary and parse the output."""
        import re
        try:
            result = subprocess.run(
                ["checksec", "--file=" + binary_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            raw = result.stdout + result.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        props = BinaryProperties(path=binary_path)
        # Parse output like: "NX: ✓", "PIE: ✓", etc.
        props.nx = "NX:" in raw and "NX: ✗" not in raw
        props.pie = "PIE:" in raw and "PIE: ✗" not in raw
        props.canary = "Canary:" in raw and "Canary: ✗" not in raw
        props.fortify = "FORTIFY:" in raw and "FORTIFY: ✗" not in raw
        if "Full RELRO" in raw:
            props.relro = "full"
        elif "Partial RELRO" in raw:
            props.relro = "partial"

        # Extract arch from file command
        try:
            file_out = subprocess.run(
                ["file", binary_path],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout
            arch_m = re.search(r"(ARM|Intel|x86-64|MIPS|PowerPC|Sparc)", file_out)
            if arch_m:
                props.arch = arch_m.group(1)
            bits_m = re.search(r"(\d+)-bit", file_out)
            if bits_m:
                props.bits = int(bits_m.group(1))
        except Exception:
            pass

        return props

    def _log_info(self, msg: str) -> None:
        log.info(msg)

    def _log_warn(self, msg: str) -> None:
        log.warn(msg)

    def _log_debug(self, msg: str) -> None:
        log.debug(msg)
