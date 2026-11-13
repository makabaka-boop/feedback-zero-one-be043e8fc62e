#!/usr/bin/env python3
"""Thin executable entry point.

Keeps the package runnable under ``python3 -I`` (isolated mode does not
put the current directory on ``sys.path``): it inserts the project root
explicitly and then hands over to :mod:`h2audit.__main__`.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from h2audit.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
