```
██████╗ ███████╗██╗   ██╗███╗   ██╗██╗ ██████╗ ███████╗
██╔══██╗██╔════╝██║   ██║████╗  ██║██║██╔════╝ ██╔════╝
██████╔╝█████╗  ██║   ██║██╔██╗ ██║██║██║  ███╗███████╗
██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║██║██║   ██║╚════██║
██║  ██║███████╗╚██████╔╝██║ ╚████║██║╚██████╔╝███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚══════╝
```

**Router_analysis** is an automated router firmware security analysis framework. Give it a firmware image, and it will extract components with binwalk, identify file types with Magika, match CVE rules, and perform static disassembly to detect known vulnerability patterns — no manual reverse engineering required.

> Currently focused on **CVE-2021-27239** (miniupnpd SSDP buffer overflow) with extensible CVE rule engine.

---

## Features

- **Zero-click analysis** — point it at a firmware image, get a security report
- **binwalk extraction** — recursive extraction of all embedded files
- **Magika identification** — AI-based file type detection for every extracted component
- **CVE rule engine** — extensible JSON rules for known vulnerability patterns
- **Static disassembly** — Ghidra / angr / radare2 integration for binary analysis
- **Code pattern matching** — regex-based vulnerability pattern detection in disassembly

## Quick Start

```bash
# Install
chmod +x setup.sh && ./setup.sh

# Analyze a firmware image
router-analysis ./firmware.bin -o ./output

# Use a specific disassembly tool
router-analysis ./firmware.bin -t ghidra
router-analysis ./firmware.bin -t angr
router-analysis ./firmware.bin -t radare2

# Skip disassembly (CVE scan only)
router-analysis ./firmware.bin --no-disassembly

# JSON output
router-analysis ./firmware.bin --json-report report.json
```

## Architecture

```
router-analysis/
  scanners/
    binwalk.py       # Firmware extraction (binwalk -eM)
    magika.py        # File type identification
    cve.py           # CVE scanning (osv.dev API + rules)
    cve_rules.py     # CVE rule definitions (JSON)
    disassembly/
      ghidra.py       # Ghidra headless analyzer
      angr.py         # angr CFG + vulnerability search
      radare2.py      # radare2 / r2pipe analyzer
      patterns.py     # Vulnerability pattern matchers
  engine/
    engine.py        # 5-phase analysis pipeline
  context.py         # FirmwareContext (analysis state)
  config.py          # Constants, dangerous functions, CVE sources
```

## CVE Rule Engine

Rules are defined in `~/.cache/router-analysis/cve_rules.json` (auto-generated on first run).

```json
{
  "cve_id": "CVE-2021-27239",
  "title": "miniupnpd SSDP Stack Buffer Overflow",
  "severity": "CRITICAL",
  "cvss": 9.8,
  "match": {
    "component": ["miniupnpd", "*upnp*"],
    "version_range": {},
    "subsystem": ["upnp", "ssdp"]
  },
  "code_patterns": [
    {
      "type": "stack_buffer_overflow",
      "pattern": "recv.*?\\n.*?strcpy",
      "description": "recv -> strcpy without length check",
      "severity": "CONFIRMED"
    }
  ],
  "string_patterns": [
    {"pattern": "miniupnpd", "description": "miniupnpd binary"}
  ]
}
```

## Requirements

- **OS**: Linux (Kali / Debian / Ubuntu)
- **Python**: >= 3.11
- **Core**: binwalk, pwntools, requests
- **Optional**: Magika, Ghidra, angr, radare2, r2pipe

## License

[MIT](LICENSE)
