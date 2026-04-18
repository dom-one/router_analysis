from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from pwn import log

from router_analysis.config import BINWALK_TIMEOUT, BINWALK_CMD
from router_analysis.scanners.base import BaseScanner, register


@register(priority=10)
class BinwalkScanner(BaseScanner):
    """Extract embedded files from a firmware image using binwalk.

    Runs ``binwalk -eM`` (extract + recursive) by default.
    """

    name = "binwalk"

    def check(self) -> bool:
        return bool(self.ctx.firmware_path) and Path(self.ctx.firmware_path).exists()

    def run(self) -> None:
        firmware_path = Path(self.ctx.firmware_path)
        work_dir = self.ctx.work_dir

        self._log_info(f"Scanning {firmware_path} ...")
        scan_output = self._run_binwalk_scan(firmware_path)
        entropy = self._parse_entropy(scan_output)

        self.ctx.entropy_regions = entropy
        self._log_info(f"Found {len(entropy)} high-entropy regions")

        self._log_info(f"Extracting to {work_dir} ...")
        extracted = self._run_binwalk_extract(firmware_path, work_dir)
        self.ctx.extracted_files = extracted
        self._log_info(f"Extracted {len(extracted)} files")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_binwalk_scan(self, firmware_path: Path) -> str:
        """Run binwalk --search to get entropy and magic signatures."""
        try:
            result = subprocess.run(
                [BINWALK_CMD, "--entropy", "--search", str(firmware_path)],
                capture_output=True,
                text=True,
                timeout=BINWALK_TIMEOUT,
            )
            return result.stdout + result.stderr
        except FileNotFoundError:
            self._log_warn(f"binwalk not found — install with: pip install binwalk")
            self.ctx.add_error("binwalk not installed")
            return ""
        except subprocess.TimeoutExpired:
            self._log_warn("binwalk scan timed out")
            self.ctx.add_error("binwalk scan timeout")
            return ""

    def _run_binwalk_extract(self, firmware_path: Path, work_dir: Path) -> list:
        """Run binwalk -eM to extract files, return list of ExtractedFile."""
        from router_analysis.context import ExtractedFile

        sig_dir = work_dir / "_firmware.extracted"
        sig_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.run(
                [BINWALK_CMD, "-eM", "--run-as=root", "-o", "0", "-C", str(sig_dir), str(firmware_path)],
                capture_output=True,
                timeout=BINWALK_TIMEOUT,
                check=False,
            )
        except FileNotFoundError:
            self._log_warn("binwalk not found")
            return []
        except subprocess.TimeoutExpired:
            self._log_warn("binwalk extraction timed out")

        files: list[ExtractedFile] = []
        if not sig_dir.exists():
            return files

        for path in sig_dir.rglob("*"):
            if path.is_file():
                sha = self._sha256(path)
                magic = self._guess_magic(path)
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                files.append(ExtractedFile(
                    path=str(path),
                    offset=0,
                    size=size,
                    file_type=magic,
                    sha256=sha,
                ))

        return files

    def _parse_entropy(self, output: str) -> list:
        """Parse binwalk entropy output into EntropyRegion list."""
        from router_analysis.context import EntropyRegion

        regions: list[EntropyRegion] = []
        # Example: "0x00000000  0.999999  High entropy data"
        pattern = re.compile(r"(0x[0-9a-f]+)\s+(0\.\d+)\s+(.*)")
        for line in output.splitlines():
            m = pattern.search(line)
            if m:
                offset = int(m.group(1), 16)
                entropy = float(m.group(2))
                desc = m.group(3).strip()
                if entropy > 0.9:
                    regions.append(EntropyRegion(
                        offset=offset,
                        size=0,
                        entropy=entropy,
                        description=desc,
                    ))
        return regions

    def _guess_magic(self, path: Path) -> str:
        """Simple magic guess via file extension + common header bytes."""
        magic_map = {
            b"\x7fELF": "ELF",
            b"\x1f\x8b": "gzip",
            b"PK\x03\x04": "ZIP/jar",
            b"\xfd7zXZ": "XZ",
            b"\x42\x5a\x68": "bzip2",
            b"\x50\x4b\x03\x04": "ZIP",
            b"sqsh": "SquashFS",
            b"hsqs": "SquashFS",
            b"Cr24": "Chrome extension",
            b"\x89PNG": "PNG",
            b"GIBF": "GIMP",
        }
        try:
            with open(path, "rb") as f:
                header = f.read(16)
            for magic, name in magic_map.items():
                if header.startswith(magic):
                    return name
        except OSError:
            pass
        return path.suffix or "unknown"

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()
