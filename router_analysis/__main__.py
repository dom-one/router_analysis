from __future__ import annotations

import logging
import sys

# Suppress verbose third-party logs before any imports trigger them
# Suppress verbose angr logs when present
for _name in ("angr", "cle", "claripy", "archinfo", "pyvex", "ailment", "capstone"):
    logging.getLogger(_name).setLevel(logging.CRITICAL)

from router_analysis.cli import main

sys.exit(main())
