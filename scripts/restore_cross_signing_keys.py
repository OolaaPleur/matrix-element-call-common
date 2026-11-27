#!/usr/bin/env python3
"""Kept for old instructions: the code moved to matrix_bot_common.restore_keys.

    <bot venv>/bin/python ../matrix-element-call-common/scripts/restore_cross_signing_keys.py <bot dir>

is the same as running `python3 -m matrix_bot_common.restore_keys` in <bot dir>.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from matrix_bot_common.restore_keys import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
