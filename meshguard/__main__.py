"""
meshguard.__main__ - Module execution entrypoint.
Allows running via `python3 -m meshguard`.
"""

import sys
from meshguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
