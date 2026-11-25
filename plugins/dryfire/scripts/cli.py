"""dryfire: replay a PreToolUse hook or rule pack against your past tool calls.

Run `python3 cli.py --help` for the commands.
"""

import os
import sys

# Keep the installed folder exactly as shipped: no __pycache__ written beside the code.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dryfire.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
