"""Safe wrappers around external OSINT command-line tools.

The wrappers never build a shell string, never inherit the parent environment,
and bound both wall-clock time and output size.  See :mod:`phishtrace.tools.runner`.
"""

from phishtrace.tools.runner import (
    ToolNotAvailable,
    ToolResult,
    ToolRunner,
    ToolTargetError,
    validate_target,
)

__all__ = [
    "ToolNotAvailable",
    "ToolResult",
    "ToolRunner",
    "ToolTargetError",
    "validate_target",
]
