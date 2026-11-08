"""
Program: WireGuard Mesh Configurator - Module CLI Execution Entrypoint
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Enable direct module execution via `python3 -m meshguard`, routing command-line arguments to the main CLI dispatcher.
"""

## Standard system module for process exit codes and argument passing
import sys

## Import the primary command-line parser and execution dispatcher
from meshguard.cli import main

## ---------------------------------------------------------------------------
## Standard Python entrypoint guard: executes only when invoked directly
## (e.g. `python3 -m meshguard` or `python3 meshguard/__main__.py`).
## ---------------------------------------------------------------------------
if __name__ == "__main__":
    ## Execute CLI main function and exit with returned integer status code
    sys.exit(main())
