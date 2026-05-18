"""Pytest config: make the `waf_rule_mpc` package importable from `server/`."""
import sys
from pathlib import Path

SERVER_DIR = Path(__file__).resolve().parent.parent / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
