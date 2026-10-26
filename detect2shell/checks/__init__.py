"""Importing this package registers every check with the registry in `base`.

Add a module here and it shows up in --list-checks and every scan.
"""

from . import log4shell  # noqa: F401
from . import spring4shell  # noqa: F401
from . import text4shell  # noqa: F401
from . import react2shell  # noqa: F401
from . import php2shell  # noqa: F401
from . import http2shell  # noqa: F401
