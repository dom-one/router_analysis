from __future__ import annotations

import subprocess
from pathlib import Path

from router_analysis.config import RADARE2_CMD, RADARE2_TIMEOUT
from router_analysis.context import DisassemblyResult
from router_analysis.scanners.base import BaseScanner, register


def run_radare2(binary_path: str) -> DisassemblyResult | None:
    """Run radare2 in batch mode to analyze a binary.

    Uses r2pipe if available, otherwise falls back to CLI.
    Returns a normalized DisassemblyResult.
    """
    r2_bin = RADARE2_CMD
    if not subprocess.run(["which", r2_bin], capture_output=True).returncode == 0:
        return None

    # Use r2pipe if available, otherwise CLI
    try:
        import r2pipe
        return _run_r2pipe(r2pipe, binary_path)
    except ImportError:
        return _run_r2_cli(binary_path)


def _run_r2pipe(r2pipe_module, binary_path: str) -> DisassemblyResult | None:
    """Analyze binary via r2pipe JSON interface."""
    try:
        r2 = r2pipe.open(binary_path, flags=["-2"])
        r2.cmd("aaa")   # analyze all
        functions_json = r2.cmd("aflj")    # list functions as JSON
        strings_json = r2.cmd("izj")        # list strings as JSON
        r2.quit()

        import json
        funcs_data = json.loads(functions_json) if functions_json else []
        strings_data = json.loads(strings_json) if strings_json else []

        functions = []
        dangerous_calls = []

        for f in funcs_data:
            fname = f.get("name", "?")
            faddr = f.get("offset", 0)
            calls = f.get("callrefs", []) + f.get("codexrefs", [])
            for call in calls:
                callee = call.get("name", call.get("addr", ""))
                if callee in (
                    "system", "popen", "strcpy", "gets", "exec",
                ):
                    dangerous_calls.append({
                        "callee": str(callee),
                        "caller": fname,
                        "address": hex(faddr) if faddr else "0x0",
                    })
            functions.append({
                "name": fname,
                "address": hex(faddr) if faddr else "0x0",
                "calls": [str(c.get("name", "")) for c in calls],
                "disasm": "",
            })

        string_list = [
            s.get("string", s.get("str", ""))
            for s in strings_data
            if isinstance(s, dict)
        ]

        return DisassemblyResult(
            binary_path=binary_path,
            tool="radare2",
            functions=functions,
            dangerous_calls=dangerous_calls,
            strings=string_list,
            cfg_size=len(funcs_data),
        )
    except Exception:
        return None


def _run_r2_cli(binary_path: str) -> DisassemblyResult | None:
    """Fallback CLI analysis when r2pipe is unavailable."""
    try:
        # Get function list
        result = subprocess.run(
            [RADARE2_CMD, "-q", "-c", "aaa", "-c", "afl", binary_path],
            capture_output=True,
            text=True,
            timeout=RADARE2_TIMEOUT,
        )
        functions = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("["):
                continue
            # afl output: "addr  type  name"
            parts = line.split(maxsplit=2)
            if len(parts) >= 2:
                functions.append({
                    "name": parts[-1] if len(parts) > 2 else parts[0],
                    "address": parts[0],
                    "calls": [],
                    "disasm": "",
                })
        return DisassemblyResult(
            binary_path=binary_path,
            tool="radare2",
            functions=functions,
            dangerous_calls=[],
            strings=[],
            cfg_size=len(functions),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


@register(priority=40)
class Radare2Scanner(BaseScanner):
    """Run radare2 static analysis on extracted ELF binaries."""

    name = "radare2"

    def check(self) -> bool:
        tool = self.kwargs.get("tool", "radare2")
        if tool not in ("radare2", "all"):
            return False
        elf_comps = [c for c in self.ctx.identified_components if c.is_executable or c.is_library]
        return len(elf_comps) > 0

    def run(self) -> None:
        from router_analysis.scanners.disassembly.patterns import match_vulnerability_patterns

        elf_comps = [
            c for c in self.ctx.identified_components
            if c.is_executable or c.is_library
        ]
        self._log_info(f"Radare2 analyzing {len(elf_comps)} binaries ...")

        for comp in elf_comps:
            self._log_info(f"  Analyzing {Path(comp.path).name} ...")
            result = run_radare2(comp.path)
            if result is None:
                self._log_warn(f"  radare2 unavailable for {comp.path}")
                continue

            self.ctx.disassembly_results[comp.path] = result
            matches = match_vulnerability_patterns(result)
            self.ctx.vulnerability_matches.extend(matches)
            if matches:
                self._log_info(f"  {len(matches)} patterns matched")
