"""ConfD Python low level module.

This module and its submodules provide Python bindings for the C APIs,
described by the confd_lib(3) man page.

The companion high level module, confd, provides an abstraction layer on top of
this module and may be easier to use.
"""
import sys
import os

from ._confd_py3 import cdb
from ._confd_py3 import maapi
from ._confd_py3 import dp
from ._confd_py3 import ha
from ._confd_py3 import lib
from ._confd_py3 import error
from ._confd_py3 import events

# Add these to sys.modules so python3 can find them
# when you do import confd._dp and family
sys.modules['_confd.cdb'] = cdb
sys.modules['_confd.maapi'] = maapi
sys.modules['_confd.dp'] = dp
sys.modules['_confd.ha'] = ha
sys.modules['_confd.error'] = error
sys.modules['_confd.events'] = events

# Python 3 version of "from lib import *"
for symbol in [x for x in dir(lib) if x[0] != '_']:
    setattr(sys.modules['_confd'], symbol, getattr(lib, symbol))

ADDR = os.environ.get('CONFD_IPC_ADDR', '127.0.0.1')
try:
    PORT = int(os.environ.get('CONFD_IPC_PORT'))
except Exception:
    pass

del symbol
del lib
del _confd_py3
del os
