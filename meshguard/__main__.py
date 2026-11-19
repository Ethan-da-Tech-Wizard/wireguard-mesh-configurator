# ==============================================================================
# Program: meshguard/__main__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Module CLI execution entrypoint enabling direct execution via
#          `python3 -m meshguard`, routing command-line arguments to the
#          main CLI parser and subcommand dispatcher.
# ==============================================================================

## Standard system module for process exit codes and argument passing
"""Entry point for `python3 -m meshguard`; delegates to meshguard.cli.main."""

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
