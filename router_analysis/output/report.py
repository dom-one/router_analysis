from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from pwn import log

if TYPE_CHECKING:
    from router_analysis.context import FirmwareContext


def _section(title: str) -> None:
    line = "=" * 60
    log.info(f"\033[1;36m{line}\033[0m")
    log.info(f"\033[1;36m  {title}\033[0m")
    log.info(f"\033[1;36m{line}\033[0m")


def _subsection(title: str) -> None:
    log.info(f"\033[1;33m--- {title} ---\033[0m")


def print_full_report(ctx: Any) -> None:
    _section("AUTOPWN ANALYSIS REPORT")

    _subsection("Target")
    log.info(f"  Binary  : {ctx.binary_path}")
    log.info(f"  Arch    : {ctx.arch} ({ctx.bits}-bit, {ctx.endian})")

    _subsection("Checksec")
    green = "\033[0;32m"
    red = "\033[0;31m"
    yellow = "\033[0;33m"
    reset = "\033[0m"
    nx_c = green if ctx.nx else red
    pie_c = green if ctx.pie else red
    can_c = green if ctx.canary else red
    relro_c = green if ctx.relro == "full" else (yellow if ctx.relro == "partial" else red)
    log.info(f"  NX      : {nx_c}{ctx.nx}{reset}")
    log.info(f"  PIE     : {pie_c}{ctx.pie}{reset}")
    log.info(f"  Canary  : {can_c}{ctx.canary}{reset}")
    log.info(f"  RELRO   : {relro_c}{ctx.relro}{reset}")
    log.info(f"  Fortify : {ctx.fortify}")

    if ctx.dangerous_funcs:
        _subsection("Dangerous Functions")
        for f in ctx.dangerous_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {red}{name}{reset} @ {addr:#x}")

    if ctx.win_funcs:
        _subsection("Win Functions")
        for f in ctx.win_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {green}{name}{reset} @ {addr:#x}")

    if ctx.input_funcs:
        _subsection("Input Functions")
        for f in ctx.input_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {name} @ {addr:#x}")

    if ctx.output_funcs:
        _subsection("Output Functions")
        for f in ctx.output_funcs:
            name = f.get("name", "?") if isinstance(f, dict) else getattr(f, "name", "?")
            addr = f.get("addr", 0) if isinstance(f, dict) else getattr(f, "addr", 0)
            log.info(f"  {name} @ {addr:#x}")

    if ctx.useful_strings:
        _subsection("Useful Strings")
        for s, addr in ctx.useful_strings.items():
            display = repr(s) if len(s) <= 60 else repr(s[:60]) + "..."
            log.info(f"  {addr:#x}: {display}")

    if ctx.got_table:
        _subsection("GOT Table")
        for name, addr in ctx.got_table.items():
            log.info(f"  {name:30s} @ {addr:#x}")

    if ctx.seccomp_rules:
        _subsection("Seccomp Rules")
        log.info(f"  execve allowed: {ctx.execve_allowed}")
        for syscall, action in ctx.seccomp_rules.items():
            log.info(f"  {syscall}: {action}")

    print_vuln_report(ctx)

    if ctx.primitives:
        _subsection("Exploit Primitives")
        for p in ctx.primitives:
            pname = p.get("name", str(p)) if isinstance(p, dict) else getattr(p, "name", str(p))
            pdesc = p.get("description", "") if isinstance(p, dict) else getattr(p, "description", "")
            log.info(f"  {green}[+]{reset} {pname}")
            if pdesc:
                log.info(f"      {pdesc}")

    if ctx.exploit_paths:
        _subsection("Exploit Paths (ranked)")
        for i, ep in enumerate(ctx.exploit_paths, 1):
            desc = ep.get("description", str(ep)) if isinstance(ep, dict) else getattr(ep, "description", str(ep))
            score = ep.get("score", 0) if isinstance(ep, dict) else getattr(ep, "score", 0)
            log.info(f"  #{i} [score={score:>5.1f}] {desc}")

    if ctx.overflow_offset >= 0:
        _subsection("Dynamic Analysis")
        log.info(f"  Overflow offset : {ctx.overflow_offset}")
        if ctx.canary_offset:
            log.info(f"  Canary offset   : {ctx.canary_offset}")
        log.info(f"  Input type      : {ctx.input_type}")
        if ctx.bad_bytes:
            log.info(f"  Bad bytes       : {ctx.bad_bytes.hex()}")
        if ctx.input_max_len:
            log.info(f"  Max input len   : {ctx.input_max_len}")

    if ctx.leaked_addrs:
        _subsection("Runtime Leaks")
        for name, addr in ctx.leaked_addrs.items():
            log.info(f"  {name:20s} = {addr:#x}")

    _section("END OF REPORT")


def print_vuln_report(ctx: Any) -> None:
    if not ctx.vulnerabilities:
        return
    _subsection("Vulnerabilities")
    red = "\033[0;31m"
    yellow = "\033[0;33m"
    reset = "\033[0m"
    for v in ctx.vulnerabilities:
        if isinstance(v, dict):
            vtype = v.get("type", "unknown")
            conf = v.get("confidence", "suspected")
            desc = v.get("description", "")
            func = v.get("function", "")
        else:
            vtype = getattr(v, "type", "unknown")
            conf = getattr(v, "confidence", "suspected")
            desc = getattr(v, "description", "")
            func = getattr(v, "function", "")

        color = red if conf in ("confirmed_static", "confirmed_dynamic") else yellow
        tag = "CONFIRMED" if "confirmed" in conf else "SUSPECTED"
        loc = f" in {func}" if func else ""
        log.info(f"  {color}[{tag}]{reset} {vtype}{loc}")
        if desc:
            log.info(f"    {desc}")

    heap_vulns = []
    if ctx.has_uaf:
        heap_vulns.append("UAF")
    if ctx.has_double_free:
        heap_vulns.append("Double Free")
    if ctx.has_heap_overflow:
        heap_vulns.append("Heap Overflow")
    if ctx.has_off_by_one:
        heap_vulns.append("Off-by-One")
    if heap_vulns:
        log.info(f"  Heap vuln flags: {', '.join(heap_vulns)}")
        if ctx.glibc_version:
            log.info(f"  glibc: {ctx.glibc_version}")


# ---------------------------------------------------------------------------
# Firmware analysis report
# ---------------------------------------------------------------------------

def _fw_section(title: str) -> None:
    line = "=" * 60
    log.info(f"\033[1;36m{line}\033[0m")
    log.info(f"\033[1;36m  {title}\033[0m")
    log.info(f"\033[1;36m{line}\033[0m")


def _fw_subsection(title: str) -> None:
    log.info(f"\033[1;33m--- {title} ---\033[0m")


def print_firmware_report(ctx: "FirmwareContext") -> None:
    """Print a formatted firmware security analysis report."""
    red = "\033[0;31m"
    yellow = "\033[0;33m"
    green = "\033[0;32m"
    cyan = "\033[0;36m"
    reset = "\033[0m"
    bold = "\033[1m"

    _fw_section("FIRMWARE SECURITY ANALYSIS REPORT")

    # --- Metadata ---
    _fw_subsection("Firmware Image")
    log.info(f"  File      : {ctx.firmware_path}")
    log.info(f"  SHA256     : {ctx.firmware_hash}")
    log.info(f"  Vendor     : {ctx.firmware_vendor or 'unknown'}")
    log.info(f"  Version    : {ctx.firmware_version or 'unknown'}")
    log.info(f"  Model      : {ctx.firmware_model or 'unknown'}")
    log.info(f"  Work dir   : {ctx.work_dir}")

    # --- Extraction summary ---
    _fw_subsection("Extraction (binwalk)")
    log.info(f"  Files extracted : {len(ctx.extracted_files)}")
    log.info(f"  High-entropy    : {len(ctx.entropy_regions)}")
    if ctx.entropy_regions:
        log.info(f"  {yellow}Note: High-entropy regions may indicate encryption or compression{reset}")

    # --- Identification summary ---
    _fw_subsection("Component Identification (magika)")
    log.info(f"  Total files    : {ctx.total_files}")
    log.info(f"  ELF binaries   : {ctx.elf_count}")
    log.info(f"  Libraries      : {ctx.lib_count}")
    lib_comps = [c for c in ctx.identified_components if c.is_library]
    if lib_comps:
        log.info("  Libraries found:")
        for c in lib_comps:
            ver = f"@{c.library_version}" if c.library_version else ""
            subsystem = f" [{c.subsystem}]" if c.subsystem else ""
            log.info(f"    {c.library_name}{ver}{subsystem} — {c.path}")

    # --- CVE findings ---
    _fw_subsection("CVE Scan Results")
    if not ctx.cve_findings:
        log.info(f"  {green}No known CVEs identified{reset}")
    else:
        # Group by severity
        by_sev: dict[str, list] = {}
        for f in ctx.cve_findings:
            by_sev.setdefault(f.severity, []).append(f)

        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        sev_colors = {
            "CRITICAL": red,
            "HIGH": red,
            "MEDIUM": yellow,
            "LOW": cyan,
            "UNKNOWN": reset,
        }
        for sev in sev_order:
            findings = by_sev.get(sev, [])
            if not findings:
                continue
            color = sev_colors.get(sev, reset)
            log.info(f"  {color}[{sev}] {len(findings)} CVE(s){reset}")
            for f in findings[:10]:   # show max 10 per severity
                log.info(
                    f"    {color}{f.cve_id}{reset} — "
                    f"{f.component}@{f.component_version} "
                    f"(confidence: {f.confidence})"
                )
            if len(findings) > 10:
                log.info(f"    ... and {len(findings) - 10} more")

    # --- Vulnerability matches from disassembly ---
    _fw_subsection("Vulnerability Patterns (static disassembly)")
    if not ctx.vulnerability_matches:
        log.info(f"  {green}No vulnerability patterns detected{reset}")
    else:
        # Group by type
        by_type: dict[str, list] = {}
        for vm in ctx.vulnerability_matches:
            by_type.setdefault(vm.vuln_type, []).append(vm)

        for vtype, matches in by_type.items():
            conf_colors = {
                "confirmed": red,
                "likely": yellow,
                "possible": cyan,
            }
            color = conf_colors.get(matches[0].confidence, reset)
            log.info(f"  {bold}{vtype}{reset}: {color}{len(matches)} match(es){reset}")
            for m in matches[:5]:
                fname = Path(m.binary_path).name
                log.info(f"    [{m.confidence}] {fname}: {m.description}")
            if len(matches) > 5:
                log.info(f"    ... and {len(matches) - 5} more")

    # --- Binary hardening ---
    _fw_subsection("Binary Hardening (checksec)")
    if not ctx.binary_properties:
        log.info("  No ELF binaries analyzed (checksec not available)")
    else:
        for path, props in ctx.binary_properties.items():
            fname = Path(path).name
            nx_c = green if props.nx else red
            pie_c = green if props.pie else yellow
            can_c = green if props.canary else yellow
            relro_c = green if props.relro == "full" else (yellow if props.relro == "partial" else red)
            log.info(f"  {fname} ({props.arch}, {props.bits}-bit)")
            log.info(f"    NX      : {nx_c}{props.nx}{reset}")
            log.info(f"    PIE     : {pie_c}{props.pie}{reset}")
            log.info(f"    Canary  : {can_c}{props.canary}{reset}")
            log.info(f"    RELRO   : {relro_c}{props.relro}{reset}")
            log.info(f"    Fortify : {props.fortify}")

    # --- Errors ---
    if ctx.errors:
        _fw_subsection("Errors")
        for err in ctx.errors:
            log.info(f"  {red}ERROR:{reset} {err}")

    # --- Overall risk ---
    _fw_section("OVERALL RISK ASSESSMENT")
    risk_colors = {
        "critical": red,
        "high": red,
        "medium": yellow,
        "low": green,
        "unknown": cyan,
    }
    risk_color = risk_colors.get(ctx.overall_risk, reset)
    log.info(f"  Overall risk: {risk_color}{bold}{ctx.overall_risk.upper()}{reset}")

    if ctx.cve_findings:
        crit = sum(1 for f in ctx.cve_findings if f.severity == "CRITICAL")
        high = sum(1 for f in ctx.cve_findings if f.severity == "HIGH")
        if crit > 0:
            log.info(f"  {red}WARNING: {crit} CRITICAL CVE(s) require immediate attention{reset}")
        if high > 0:
            log.info(f"  {red}WARNING: {high} HIGH severity CVE(s) should be addressed{reset}")

    _fw_section("END OF REPORT")

