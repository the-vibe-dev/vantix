from __future__ import annotations

import sys
from pathlib import Path

# Put sdk/ on sys.path so ``import vantix_sdk`` resolves as a third-party
# consumer would after ``pip install vantix-sdk``.
_SDK_ROOT = Path(__file__).resolve().parents[2] / "sdk"
if str(_SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(_SDK_ROOT))
