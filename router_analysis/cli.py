from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path

from autopwn import __version__
from router_analysis.context import FirmwareContext
from router_analysis.engine.engine import PhasedFirmwareEngine
from router_analysis.output.logger import banner, setup_logger


def _kill_group(signum, frame) -> None:
    try:
        os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)
    except (ProcessLookupError, OSError):
        pass
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="router-analysis",
        description=f"Router_analysis v{__version__} — Automated Router Firmware Security Analysis",
    )
    parser.add_argument(
        "firmware",
        help="path to firmware image file",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        help="output directory for extraction and reports",
    )
    parser.add_argument(
        "-t", "--tool",
        choices=["ghidra", "angr", "radare2", "all"],
        default="ghidra",
        help="static disassembly tool (default: ghidra)",
    )
    parser.add_argument(
        "--cve-db",
        metavar="PATH",
        help="path to local CVE database JSON (default: use osv.dev API)",
    )
    parser.add_argument(
        "-d", "--deep-extract",
        action="store_true",
        help="deep extraction mode (recursive binwalk)",
    )
    parser.add_argument(
        "--no-disassembly",
        action="store_true",
        help="skip static disassembly phase",
    )
    parser.add_argument(
        "-a", "--analyze-only",
        action="store_true",
        help="stop after analysis, do not generate report",
    )
    parser.add_argument(
        "--blackbox",
        action="store_true",
        help="skip disassembly (equivalent to --no-disassembly)",
    )
    parser.add_argument(
        "-v", "--verbosity",
        action="count",
        default=0,
        dest="verbosity",
        help="increase verbosity (-v info, -vv debug)",
    )
    parser.add_argument(
        "--json-report",
        metavar="PATH",
        help="write JSON report to file",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        help="non-interactive batch mode",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGINT, _kill_group)
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logger(args.verbosity)
    banner()

    # Validate firmware file
    if not Path(args.firmware).exists():
        log.error(f"File not found: {args.firmware}")
        return 1

    # Build context
    ctx = FirmwareContext(firmware_path=str(Path(args.firmware).resolve()))

    # --no-disassembly and --blackbox are equivalent
    if args.blackbox:
        args.no_disassembly = True

    # Run engine
    try:
        engine = PhasedFirmwareEngine(ctx, args)
        exit_code = engine.run()
    except FileNotFoundError as exc:
        from pwn import log as pwn_log
        pwn_log.failure(str(exc))
        return 1
    except Exception as exc:
        from pwn import log as pwn_log
        pwn_log.failure(f"Fatal error: {exc}")
        return 1

    # Write JSON report if requested
    if args.json_report:
        import json
        report_data = _build_json_report(ctx)
        out_path = Path(args.json_report)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report_data, indent=2, default=str))
        from pwn import log as pwn_log
        pwn_log.info(f"JSON report written to {out_path}")

    return exit_code


def _build_json_report(ctx: FirmwareContext) -> dict:
    """Serialize FirmwareContext into a JSON-serializable dict."""
    return {
        "firmware": {
            "path": ctx.firmware_path,
            "sha256": ctx.firmware_hash,
            "vendor": ctx.firmware_vendor,
            "version": ctx.firmware_version,
            "model": ctx.firmware_model,
        },
        "extraction": {
            "file_count": len(ctx.extracted_files),
            "entropy_regions": len(ctx.entropy_regions),
        },
        "identification": {
            "total": ctx.total_files,
            "elf_count": ctx.elf_count,
            "lib_count": ctx.lib_count,
            "components": [
                {
                    "path": c.path,
                    "label": c.magika_label,
                    "library": f"{c.library_name}@{c.library_version}" if c.library_version else c.library_name,
                    "subsystem": c.subsystem,
                }
                for c in ctx.identified_components
            ],
        },
        "cve_findings": [
            {
                "cve_id": f.cve_id,
                "component": f.component,
                "version": f.component_version,
                "severity": f.severity,
                "severity_score": f.severity_score,
                "confidence": f.confidence,
                "affected_binary": Path(f.affected_binary).name,
                "references": f.references,
            }
            for f in ctx.cve_findings
        ],
        "vulnerabilities": [
            {
                "type": vm.vuln_type,
                "binary": Path(vm.binary_path).name,
                "confidence": vm.confidence,
                "description": vm.description,
                "cve_id": vm.cve_id,
            }
            for vm in ctx.vulnerability_matches
        ],
        "binary_properties": {
            Path(p).name: {
                "arch": bp.arch,
                "bits": bp.bits,
                "nx": bp.nx,
                "pie": bp.pie,
                "canary": bp.canary,
                "relro": bp.relro,
                "fortify": bp.fortify,
            }
            for p, bp in ctx.binary_properties.items()
        },
        "errors": ctx.errors,
        "overall_risk": ctx.overall_risk,
    }
