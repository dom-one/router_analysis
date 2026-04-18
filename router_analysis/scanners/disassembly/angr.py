from __future__ import annotations

from pathlib import Path

from router_analysis.config import ANGR_TIMEOUT, DANGEROUS_FUNCS
from router_analysis.context import DisassemblyResult
from router_analysis.scanners.base import BaseScanner, register


def run_angr(binary_path: str) -> DisassemblyResult | None:
    """Run angr CFG analysis on a binary and return a DisassemblyResult.

    Returns None if angr is unavailable or the binary cannot be loaded.
    """
    try:
        import angr
        import claripy
    except ImportError:
        return None

    try:
        proj = angr.Project(binary_path, auto_load_libs=False, load_options={
            "main_opts": {"backend": "blob"}
        })
    except Exception:
        return None

    functions = []
    dangerous_calls = []

    try:
        cfg = proj.analyses.CFGFast(
            data_references=True,
            resolve_indirect_calls=True,
            timeout=ANGR_TIMEOUT,
        )
    except Exception:
        cfg = None

    if cfg:
        for func_node in cfg.functions.values():
            fname = func_node.name
            addr = func_node.address
            func_info = {"name": fname, "address": hex(addr) if addr else "0x0", "calls": [], "disasm": ""}

            if fname in DANGEROUS_FUNCS:
                dangerous_calls.append({"callee": fname, "address": hex(addr)})

            # Collect outgoing calls
            if hasattr(func_node, "get_outgoing_edges"):
                for edge in func_node.get_outgoing_edges():
                    callee_name = cfg.functions.get(edge.target.function_address, None)
                    if callee_name:
                        func_info["calls"].append(callee_name.name)

            # Basic disassembly via block decompilation
            try:
                if func_node.addr:
                    block = proj.factory.block(func_node.addr)
                    func_info["disasm"] = block.vex.__str__()
            except Exception:
                pass

            functions.append(func_info)

    # Collect strings
    string_list = []
    try:
        string_mgr = proj.analyses.StringExtractor()
        string_list = string_mgr.get_result().strings if string_mgr.get_result() else []
    except Exception:
        pass

    return DisassemblyResult(
        binary_path=binary_path,
        tool="angr",
        functions=functions,
        dangerous_calls=dangerous_calls,
        strings=[s.decode() if isinstance(s, bytes) else str(s) for s in string_list],
        cfg_size=len(functions),
    )


@register(priority=40)
class AngrScanner(BaseScanner):
    """Run angr-based static analysis on extracted ELF binaries."""

    name = "angr"

    def check(self) -> bool:
        tool = self.kwargs.get("tool", "angr")
        if tool not in ("angr", "all"):
            return False
        elf_comps = [c for c in self.ctx.identified_components if c.is_executable or c.is_library]
        return len(elf_comps) > 0

    def run(self) -> None:
        from router_analysis.scanners.disassembly.patterns import match_vulnerability_patterns

        elf_comps = [
            c for c in self.ctx.identified_components
            if c.is_executable or c.is_library
        ]
        self._log_info(f"Angr analyzing {len(elf_comps)} binaries ...")

        for comp in elf_comps:
            self._log_info(f"  Analyzing {Path(comp.path).name} ...")
            result = run_angr(comp.path)
            if result is None:
                self._log_warn(f"  angr failed on {comp.path}")
                continue

            self.ctx.disassembly_results[comp.path] = result
            matches = match_vulnerability_patterns(result)
            self.ctx.vulnerability_matches.extend(matches)
            if matches:
                self._log_info(f"  {len(matches)} vulnerability patterns matched")
