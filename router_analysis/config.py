from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

CACHE_DIR: Path = Path.home() / ".cache" / "router-analysis"

# Default output directory when -o is not specified
DEFAULT_OUTPUT: Path = Path("./firmware_output")

# ---------------------------------------------------------------------------
# Tool paths (can be overridden via environment or config)
# ---------------------------------------------------------------------------

BINWALK_CMD: str = "binwalk"
MAGIKA_CMD: str = "magika"
GHIDRA_HEADLESS: str = "analyzeHeadless"
RADARE2_CMD: str = "r2"

# ---------------------------------------------------------------------------
# CVE data sources
# ---------------------------------------------------------------------------

OSV_API_URL: str = "https://api.osv.dev/v1/query"
NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Local CVE database fallback path (JSON)
CVE_DB_PATH: Path = CACHE_DIR / "cve_db.json"

# ---------------------------------------------------------------------------
# Timeouts (seconds)
# ---------------------------------------------------------------------------

RECV_TIMEOUT: int = 5
GHIDRA_TIMEOUT: int = 600      # 10 min per binary
ANGR_TIMEOUT: int = 300        # 5 min per binary
RADARE2_TIMEOUT: int = 120     # 2 min per binary
BINWALK_TIMEOUT: int = 600     # 10 min total
MAGIKA_TIMEOUT: int = 30       # per file

# ---------------------------------------------------------------------------
# Known dangerous functions (mirrored from CTF config, firmware-relevant)
# ---------------------------------------------------------------------------

DANGEROUS_FUNCS: list[str] = [
    # Buffer / string
    "gets", "strcpy", "strcat", "sprintf", "vsprintf",
    "scanf", "fscanf", "sscanf", "vscanf", "vfscanf",
    "strncpy", "strncat", "snprintf", "vsnprintf",
    # Memory
    "memcpy", "memmove", "bcopy",
    # Command execution
    "system", "popen", "exec", "execl", "execlp", "execle",
    "execv", "execvp", "execve", "do_system",
    # Network / socket
    "recv", "recvfrom", "recvmsg",
    "send", "sendto", "sendmsg",
    # File
    "fopen", "open", "openat", "read", "write",
    # Format string
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
]

# Functions that warrant immediate attention
CRITICAL_FUNCS: list[str] = [
    "system", "popen", "execl", "execv", "execve",
    "gets", "strcpy", "strcat",
]

# ---------------------------------------------------------------------------
# Vulnerability pattern types
# ---------------------------------------------------------------------------

VULN_TYPES: list[str] = [
    "buffer_overflow",
    "command_injection",
    "format_string",
    "integer_overflow",
    "use_after_free",
    "double_free",
    "heap_overflow",
    "stack_overflow",
    "path_traversal",
    "sql_injection",
    "xss",
    "deserialization",
    "race_condition",
    "hardcoded_credentials",
    "backdoor",
    "deprecated_crypto",
]

# ---------------------------------------------------------------------------
# Library fingerprinting (name → common version extraction regex)
# ---------------------------------------------------------------------------

LIBRARY_PATTERNS: dict[str, str] = {
    "libcrypto":   r"libcrypto\.so\.(.+)",
    "libssl":      r"libssl\.so\.(.+)",
    "libz":        r"libz\.so\.(.+)",
    "libssl3":     r"libssl\.so\.(.+)",
    "libcurl":     r"libcurl\.so\.(.+)",
    "libpng":      r"libpng.*?so[\._]([\d\.]+)",
    "libjpeg":     r"libjpeg\.so\.(.+)",
    "libxml2":     r"libxml2\.so\.(.+)",
    "libjson":     r"libjson-c\.so\.(.+)",
    "libbusybox":  r"busybox",
    "libssl":      r"openssl",
    "uclibc":      r"uClibc",
    "musl":        r"musl",
    "glibc":       r"GLIBC\.([\d.]+)",
}

# Common subsystem keywords for firmware classification
SUBSYSTEM_KEYWORDS: dict[str, list[str]] = {
    "linux-kernel": ["vmlinux", "bzImage", "Image", "/lib/modules/"],
    "u-boot":       ["U-Boot", "u-boot", "SPL", "MLO"],
    "openwrt":      ["OpenWrt", "/etc/config/"],
    "busybox":      ["BusyBox", "/bin/sh"],
    "wrt54g":       ["WRT54G", "Broadcom"],
}

# ---------------------------------------------------------------------------
# CVE severity thresholds
# ---------------------------------------------------------------------------

SEVERITY_CRITICAL: float = 9.0
SEVERITY_HIGH: float = 7.0
SEVERITY_MEDIUM: float = 4.0

RISK_FROM_SEVERITY: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "unknown",
}
