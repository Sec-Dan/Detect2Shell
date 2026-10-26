"""Detect2Shell - an authorised exposure scanner for the *2Shell / *4Shell
remote code execution family (Log4Shell, Spring4Shell, Text4Shell, React2Shell,
PHP2Shell and the Node2Shell/Python2Shell/HTTP2Shell Brotli bug).

The package is deliberately built on the Python standard library alone so it can
be dropped onto any box with a working Python 3 and no install step.
"""

__version__ = "0.1.0"

PROJECT_NAME = "Detect2Shell"
REPO_URL = "https://github.com/Sec-Dan/Detect2Shell"
AUTHOR = "DanSec"

# Minimum interpreter we test against. Kept low so the tool runs on the kind of
# older, half-forgotten servers that tend to still be carrying these bugs.
MIN_PYTHON = (3, 8)
