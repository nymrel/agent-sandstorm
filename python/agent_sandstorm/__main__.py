"""
__main__.py: Executable module entry point for python -m agent_sandstorm
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
