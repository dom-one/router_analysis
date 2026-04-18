from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

from pwn import log

from router_analysis.config import MAGIKA_TIMEOUT, MAGIKA_CMD
from router_analysis.scanners.base import BaseScanner, register


@register(priority=20)
class MagikaScanner(BaseScanner):
    """Identify file types of extracted firmware components using Magika."""

    name = "magika"

    # File extensions associated with each category
    EXECUTABLE_EXTS = {
        ".elf", ".exe", ".bin", ".ko", ".axf", ".img",
        ".uimg", ".uboot", ".pac", ".app",
    }
    LIBRARY_EXTS = {
        ".so", ".so.1", ".so.2", ".so.3",
        ".dylib", ".a", ".lib", ".dll",
    }
    CONFIG_EXTS = {
        ".conf", ".config", ".cfg", ".ini", ".json",
        ".xml", ".yaml", ".yml", ".toml",
    }
    SCRIPT_EXTS = {
        ".sh", ".py", ".pl", ".rb", ".lua", ".js",
        ".bash", ".ash", ".zsh",
    }

    def check(self) -> bool:
        return len(self.ctx.extracted_files) > 0

    def run(self) -> None:
        files = self.ctx.extracted_files
        self._log_info(f"Identifying {len(files)} files with Magika ...")

        identified = []
        for ef in files:
            result = self._identify_file(Path(ef.path))
            identified.append(result)

        self.ctx.identified_components.extend(identified)
        self.ctx.total_files = len(identified)
        self.ctx.elf_count = sum(1 for i in identified if i.magika_label == "ELF")
        self.ctx.lib_count = sum(1 for i in identified if i.is_library)

        self._log_info(
            f"Identified: {self.ctx.elf_count} ELF, "
            f"{self.ctx.lib_count} libs, "
            f"{self.ctx.total_files} total"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _identify_file(self, path: Path) -> "IdentifiedFile":
        """Run magika on a single file and parse the result."""
        from router_analysis.context import IdentifiedFile

        label = ""
        mime = ""
        try:
            result = subprocess.run(
                [MAGIKA_CMD, "-r", "-I", str(path)],
                capture_output=True,
                text=True,
                timeout=MAGIKA_TIMEOUT,
            )
            label, mime = self._parse_magika_output(result.stdout)
        except FileNotFoundError:
            self._log_warn("magika not found — run: pip install magika")
            self.ctx.add_error("magika not installed")
        except subprocess.TimeoutExpired:
            self._log_warn(f"magika timed out on {path.name}")

        # Fallback: guess from extension and magic header
        if not label:
            label = self._fallback_identify(path)

        # Version extraction for libraries
        lib_name, lib_ver = self._extract_library_info(path.name)

        # Classify type
        is_executable = (
            label in ("ELF", "PE", "Mach-O")
            or path.suffix in self.EXECUTABLE_EXTS
        )
        is_library = (
            label == "ELF" and ".so" in path.name
            or path.suffix in self.LIBRARY_EXTS
        )
        is_config = (
            label in ("JSON", "XML", "YAML", "text")
            or path.suffix in self.CONFIG_EXTS
        )
        is_script = label in ("script", "Bourne shell", "Python") or path.suffix in self.SCRIPT_EXTS

        return IdentifiedFile(
            path=str(path),
            magika_label=label,
            mime_type=mime,
            is_executable=is_executable,
            is_library=is_library,
            is_config=is_config,
            is_script=is_script,
            library_name=lib_name,
            library_version=lib_ver,
            subsystem=self._guess_subsystem(path),
        )

    def _parse_magika_output(self, raw: str) -> tuple[str, str]:
        """Parse magika -r -I output into (label, mime_type)."""
        # magika -I outputs: "ELF  application/x-executable"
        parts = raw.strip().split()
        if len(parts) >= 1:
            label = parts[0]
        else:
            label = ""
        if len(parts) >= 2:
            mime = parts[1]
        else:
            mime = ""
        return label, mime

    def _fallback_identify(self, path: Path) -> str:
        """Fallback identification when magika is unavailable."""
        magic_map = {
            b"\x7fELF": "ELF",
            b"\x1f\x8b": "gzip",
            b"PK\x03\x04": "ZIP",
            b"\x89PNG": "PNG",
            b"\xfd7zXZ": "XZ",
            b"\x42\x5a\x68": "bzip2",
        }
        try:
            with open(path, "rb") as f:
                header = f.read(8)
            for magic, name in magic_map.items():
                if header.startswith(magic):
                    return name
        except OSError:
            pass

        ext_map = {
            ".elf": "ELF",
            ".sh": "shell script",
            ".py": "Python",
            ".json": "JSON",
            ".xml": "XML",
            ".conf": "text",
        }
        return ext_map.get(path.suffix.lower(), "unknown")

    def _extract_library_info(self, name: str) -> tuple[str, str]:
        """Extract library name and version from filename.

        Examples:
          libcrypto.so.1.1.0i  -> ("libcrypto", "1.1.0i")
          libssl.so.3          -> ("libssl", "3")
          busybox               -> ("busybox", "")
          libcurl.so.4.6.0      -> ("libcurl", "4.6.0")
        """
        # Pattern: libFOO.so.MAJOR.MINOR.PATCH
        so_pattern = re.compile(r"(lib[\w\-]+)\.so\.?(\d[\d.]*)")
        m = so_pattern.search(name)
        if m:
            return m.group(1), m.group(2)

        # busybox — no version
        if "busybox" in name.lower():
            return "busybox", ""

        # uclibc / musl / glibc
        for lib in ("uClibc", "musl", "glibc"):
            if lib.lower() in name.lower():
                ver = re.search(r"([\d.]+)", name)
                return lib, ver.group(1) if ver else ""

        return "", ""

    def _guess_subsystem(self, path: Path) -> str:
        """Guess the firmware subsystem from path context."""
        rel = str(path)
        for subsystem, keywords in {
            "linux-kernel": ["vmlinux", "ko", "/lib/modules/"],
            "u-boot": ["u-boot", "SPL", "MLO"],
            "openwrt": ["openwrt", "/etc/config/"],
            "busybox": ["busybox", "/bin/", "/sbin/"],
            "wrt54g": ["broadcom", "bcm"],
        }.items():
            if any(kw.lower() in rel.lower() for kw in keywords):
                return subsystem
        return ""

    def get_findings(self) -> list[dict[str, Any]]:
        return [
            {
                "path": ic.path,
                "label": ic.magika_label,
                "library": f"{ic.library_name}@{ic.library_version}" if ic.library_version else ic.library_name,
                "executable": ic.is_executable,
                "subsystem": ic.subsystem,
            }
            for ic in self.ctx.identified_components
        ]
