from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from router_analysis.config import GHIDRA_HEADLESS, GHIDRA_TIMEOUT
from router_analysis.context import BinaryProperties, DisassemblyResult
from router_analysis.scanners.base import BaseScanner, register


# ---------------------------------------------------------------------------
# Ghidra headless helper
# ---------------------------------------------------------------------------

def run_ghidra(binary_path: str, work_dir: Path) -> DisassemblyResult | None:
    """Run Ghidra headless analyzer on a binary.

    Returns a normalized DisassemblyResult, or None if Ghidra is unavailable.
    """
    ghidra_repo = work_dir / ".ghidra"
    output_dir = work_dir / ".ghidra_output"

    # Check ghidra is available
    ghidra_bin = shutil.which(GHIDRA_HEADLESS)
    if not ghidra_bin:
        for candidate in [
            Path("/opt/ghidra/support/analyzeHeadless"),
            Path.home() / "ghidra" / "support" / "analyzeHeadless",
        ]:
            if candidate.exists():
                ghidra_bin = str(candidate)
                break

    if not ghidra_bin:
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    ghidra_repo.mkdir(parents=True, exist_ok=True)

    # Write a Ghidra Python script to export analysis results as JSON
    script = work_dir / "_ghidra_export.py"
    script.write_text(_GHIDRA_SCRIPT)

    try:
        subprocess.run(
            [
                ghidra_bin,
                str(ghidra_repo),
                str(output_dir),
                "-import", binary_path,
                "-scriptPath", str(work_dir),
                "-postScript", "_ghidra_export.py",
                "-analysisTimeout", str(GHIDRA_TIMEOUT),
            ],
            capture_output=True,
            text=True,
            timeout=GHIDRA_TIMEOUT + 60,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

    json_out = output_dir / "_ghidra_result.json"
    if not json_out.exists():
        return None

    data = json.loads(json_out.read_text())
    return _parse_ghidra_json(data, binary_path)


def _parse_ghidra_json(data: dict, binary_path: str) -> DisassemblyResult:
    """Normalize Ghidra JSON output into a DisassemblyResult."""
    functions = []
    dangerous_calls = []

    for func in data.get("functions", []):
        fname = func.get("name", "")
        addr_str = func.get("address", "0x0")
        for call in func.get("calls", []):
            dangerous_calls.append({
                "callee": call,
                "caller": fname,
                "address": addr_str,
            })
        functions.append({
            "name": fname,
            "address": addr_str,
            "disasm": "\n".join(func.get("disasm_lines", [])),
            "calls": func.get("calls", []),
        })

    return DisassemblyResult(
        binary_path=binary_path,
        tool="ghidra",
        functions=functions,
        dangerous_calls=dangerous_calls,
        strings=data.get("strings", []),
        cfg_size=data.get("function_count", 0),
    )


# ---------------------------------------------------------------------------
# GhidraScanner
# ---------------------------------------------------------------------------

@register(priority=40)
class GhidraScanner(BaseScanner):
    """Run Ghidra headless analysis on extracted ELF binaries."""

    name = "ghidra"

    def check(self) -> bool:
        tool = self.kwargs.get("tool", "ghidra")
        if tool not in ("ghidra", "all"):
            return False
        return len(self.ctx.identified_components) > 0

    def run(self) -> None:
        from router_analysis.scanners.disassembly.patterns import match_vulnerability_patterns

        elf_comps = [
            c for c in self.ctx.identified_components
            if c.is_executable or c.is_library
        ]
        self._log_info(f"Ghidra analyzing {len(elf_comps)} binaries ...")

        for comp in elf_comps:
            self._log_info(f"  Analyzing {Path(comp.path).name} ...")
            result = run_ghidra(comp.path, self.ctx.work_dir)
            if result is None:
                self._log_warn(f"  Ghidra unavailable or failed for {comp.path}")
                continue

            self.ctx.disassembly_results[comp.path] = result
            matches = match_vulnerability_patterns(result)
            self.ctx.vulnerability_matches.extend(matches)
            if matches:
                self._log_info(f"  {len(matches)} patterns matched")


# ---------------------------------------------------------------------------
# Ghidra Python export script (written to disk, passed via -postScript)
# ---------------------------------------------------------------------------

_GHIDRA_SCRIPT = r'''
import json
import os
from ghidra.program.model.listing import Function
from ghidra.app.script import GhidraScript

class ExportScript(GhidraScript):
    def run(self):
        output_dir = os.path.join(os.path.dirname(self.currentProgram.getExecutablePath()), ".ghidra_output")
        os.makedirs(output_dir, exist_ok=True)

        result = {
            "program": self.currentProgram.getName(),
            "functions": [],
            "strings": [],
            "function_count": 0,
        }

        fm = self.currentProgram.getFunctionManager()
        for func in fm.getFunctions(True):
            func_data = {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "calls": [],
                "disasm_lines": [],
            }
            for ref in func.getReferences():
                callee = getFunctionAt(ref.getToAddress())
                if callee:
                    func_data["calls"].append(callee.getName())
            listing = self.currentProgram.getListing()
            addr = func.getEntryPoint()
            insns = listing.getInstructions(addr, True)
            count = 0
            for insn in insns:
                func_data["disasm_lines"].append(str(insn))
                count += 1
                if count >= 64:
                    break
            result["functions"].append(func_data)
            result["function_count"] += 1

        data_iter = self.currentProgram.getListing().getDefinedData(True)
        for data in data_iter:
            if data.hasStringValue():
                s = data.getValue()
                if s and len(s) > 4:
                    result["strings"].append(str(s))

        out_path = os.path.join(output_dir, "_ghidra_result.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f)
'''
