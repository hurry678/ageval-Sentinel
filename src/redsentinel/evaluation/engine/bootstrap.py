"""Add integrated-system package roots to sys.path for scripts and runners."""
import sys
from pathlib import Path

_SYSTEM_ROOT = Path(__file__).resolve().parents[4]
for _p in (
    _SYSTEM_ROOT / "src",
    _SYSTEM_ROOT,
):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)


def setup_paths():
    """Call at top of runners/scripts before other imports."""
    pass  # side effect on import
