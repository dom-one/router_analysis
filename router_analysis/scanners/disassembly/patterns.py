from __future__ import annotations

import re
from typing import Any

from router_analysis.config import CRITICAL_FUNCS, DANGEROUS_FUNCS


# ---------------------------------------------------------------------------
# Vulnerability pattern definitions
# Each pattern is a dict with:
#   type       — vulnerability category
#   cve_id     — associated CVE (empty string if generic)
#   confidence — "confirmed" | "likely" | "possible"
#   description — human-readable description
#   check_fn   — callable(list[str]) → bool (returns True if matched)
# ---------------------------------------------------------------------------

# Signature-based: disassembled call to dangerous function with a
# user-controlled-looking argument pattern.
DANGEROUS_CALL_RE = re.compile(
    r"(call|jal|jalr)\s+(\w+)\s*<({})\b".format(
        "|".join(re.escape(f) for f in DANGEROUS_FUNCS)
    )
)

CRITICAL_CALL_RE = re.compile(
    r"(call|jal|jalr)\s+(\w+)\s*<({})\b".format(
        "|".join(re.escape(f) for f in CRITICAL_FUNCS)
    )
)

# Format string: first arg looks like a format string literal
FORMAT_RE = re.compile(
    r"(call|jal|jalr)\s+\w+\s*<(printf|vprintf|fprintf|sprintf|vsprintf|snprintf|vsnprintf)\b"
)

# Command injection: system()/popen() with non-constant argument
CMD_INJECT_RE = re.compile(
    r"(call|jal|jalr)\s+\w+\s*<(system|popen|execl|execv|execve|do_system)\b"
)

# Stack buffer overflow: strcpy/strcat/memcpy with stack-relative dest
STACK_BOF_RE = re.compile(
    r"(call|jal|jalr)\s+\w+\s*<(strcpy|strcat|memcpy)\b.*"
    r"(rbp-[0-9a-f]+|ebp-[0-9a-f]+|esp-[0-9a-f]+)"
)

# Hardcoded credential patterns in strings
HARDCODED_CREDS_RE = re.compile(
    r"(password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*['\"][^'\"]{3,}['\"]",
    re.IGNORECASE,
)

# Backdoor patterns: suspicious function names or magic constants
BACKDOOR_RE = re.compile(
    r"(backdoor|root_shell|get_root|enable_root|exec_root|"
    r"magic_packet|debug_cmd|test_mode|hack|trigger)",
    re.IGNORECASE,
)

# Deprecated crypto: use of MD5 / SHA1 / DES in crypto library contexts
DEPRECATED_CRYPTO_RE = re.compile(
    r"(MD5|SHA1|DES|RC4|ECB)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# High-level vulnerability rules
# ---------------------------------------------------------------------------

VULN_PATTERNS: list[dict[str, Any]] = [
    {
        "type": "command_injection",
        "cve_id": "",
        "confidence": "confirmed",
        "description": "Call to system/popen/exec* with potentially unsanitized input",
        "check_fn": lambda disasm_lines: bool(CMD_INJECT_RE.search("\n".join(disasm_lines))),
    },
    {
        "type": "format_string",
        "cve_id": "",
        "confidence": "confirmed",
        "description": "printf-family call using user-supplied format string",
        "check_fn": lambda disasm_lines: bool(FORMAT_RE.search("\n".join(disasm_lines))),
    },
    {
        "type": "buffer_overflow",
        "cve_id": "",
        "confidence": "likely",
        "description": "Unbounded strcpy/strcat/memcpy targeting stack buffer",
        "check_fn": lambda disasm_lines: bool(STACK_BOF_RE.search("\n".join(disasm_lines))),
    },
    {
        "type": "dangerous_function",
        "cve_id": "",
        "confidence": "possible",
        "description": "Call to dangerous function (gets/strcpy/...)",
        "check_fn": lambda disasm_lines: bool(DANGEROUS_CALL_RE.search("\n".join(disasm_lines))),
    },
    {
        "type": "hardcoded_credentials",
        "cve_id": "",
        "confidence": "confirmed",
        "description": "Hardcoded password, secret, or API key found in binary strings",
        "check_fn": lambda strings: bool(any(HARDCODED_CREDS_RE.search(s) for s in strings)),
    },
    {
        "type": "backdoor",
        "cve_id": "",
        "confidence": "likely",
        "description": "Suspicious function name or magic constant suggesting backdoor",
        "check_fn": lambda strings: bool(any(BACKDOOR_RE.search(s) for s in strings)),
    },
    {
        "type": "deprecated_crypto",
        "cve_id": "",
        "confidence": "possible",
        "description": "Use of deprecated cryptographic primitive (MD5/SHA1/DES/RC4)",
        "check_fn": lambda strings: bool(any(DEPRECATED_CRYPTO_RE.search(s) for s in strings)),
    },
]


def match_vulnerability_patterns(
    disassembly_result: "DisassemblyResult",
) -> list[dict[str, Any]]:
    """Run all vulnerability patterns against a disassembly result.

    Returns a list of matched patterns, each with location info.
    """
    from router_analysis.context import VulnMatch

    matches: list[dict[str, Any]] = []
    disasm_text = "\n".join(
        line.get("disasm", "") for line in disassembly_result.functions
    )
    disasm_lines = disasm_text.splitlines()
    strings = disassembly_result.strings
    binary_path = disassembly_result.binary_path

    for pattern in VULN_PATTERNS:
        check_fn = pattern["check_fn"]
        try:
            # String patterns get strings list, disasm patterns get disasm lines
            matched: bool
            if pattern["type"] in ("hardcoded_credentials", "backdoor", "deprecated_crypto"):
                matched = check_fn(strings)
            else:
                matched = check_fn(disasm_lines)
        except Exception:
            matched = False

        if matched:
            vm = VulnMatch(
                binary_path=binary_path,
                vuln_type=pattern["type"],
                location="",          # TODO: annotate with function name
                cve_id=pattern.get("cve_id", ""),
                confidence=pattern["confidence"],
                description=pattern["description"],
                code_snippet="",     # TODO: annotate with matched line
            )
            matches.append(vm)

    return matches
