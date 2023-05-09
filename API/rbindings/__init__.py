# -*- coding: utf-8 -*-
from operator import attrgetter
from pyangbind.lib.yangtypes import RestrictedPrecisionDecimalType
from pyangbind.lib.yangtypes import RestrictedClassType
from pyangbind.lib.yangtypes import TypedListType
from pyangbind.lib.yangtypes import YANGBool
from pyangbind.lib.yangtypes import YANGListType
from pyangbind.lib.yangtypes import YANGDynClass
from pyangbind.lib.yangtypes import ReferenceType
from pyangbind.lib.base import PybindBase
from collections import OrderedDict
from decimal import Decimal
from bitarray import bitarray
import six

# PY3 support of some PY2 keywords (needs improved)
if six.PY3:
  import builtins as __builtin__
  long = int
elif six.PY2:
  import __builtin__

class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf-i2nsf-registration-interface. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module defines a YANG data model for I2NSF
Registration Interface.

The key words 'MUST', 'MUST NOT', 'REQUIRED', 'SHALL',
'SHALL NOT', 'SHOULD', 'SHOULD NOT', 'RECOMMENDED',
'NOT RECOMMENDED', 'MAY', and 'OPTIONAL' in this
document are to be interpreted as described in BCP 14
(RFC 2119) (RFC 8174) when, and only when, they appear
in all capitals, as shown here.

Copyright (c) 2023 IETF Trust and the persons
identified as authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or
without modification, is permitted pursuant to, and subject
to the license terms contained in, the Revised BSD License
set forth in Section 4.c of the IETF Trust's Legal Provisions
Relating to IETF Documents
(https://trustee.ietf.org/license-info).

This version of this YANG module is part of RFC XXXX; see
the RFC itself for full legal notices.
  """
  _pyangbind_elements = {}

  

class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf-i2nsf-registration-interface. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module defines a YANG data model for I2NSF
Registration Interface.

The key words 'MUST', 'MUST NOT', 'REQUIRED', 'SHALL',
'SHALL NOT', 'SHOULD', 'SHOULD NOT', 'RECOMMENDED',
'NOT RECOMMENDED', 'MAY', and 'OPTIONAL' in this
document are to be interpreted as described in BCP 14
(RFC 2119) (RFC 8174) when, and only when, they appear
in all capitals, as shown here.

Copyright (c) 2023 IETF Trust and the persons
identified as authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or
without modification, is permitted pursuant to, and subject
to the license terms contained in, the Revised BSD License
set forth in Section 4.c of the IETF Trust's Legal Provisions
Relating to IETF Documents
(https://trustee.ietf.org/license-info).

This version of this YANG module is part of RFC XXXX; see
the RFC itself for full legal notices.
  """
  _pyangbind_elements = {}

  

class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf-i2nsf-registration-interface. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: This module defines a YANG data model for I2NSF
Registration Interface.

The key words 'MUST', 'MUST NOT', 'REQUIRED', 'SHALL',
'SHALL NOT', 'SHOULD', 'SHOULD NOT', 'RECOMMENDED',
'NOT RECOMMENDED', 'MAY', and 'OPTIONAL' in this
document are to be interpreted as described in BCP 14
(RFC 2119) (RFC 8174) when, and only when, they appear
in all capitals, as shown here.

Copyright (c) 2023 IETF Trust and the persons
identified as authors of the code. All rights reserved.

Redistribution and use in source and binary forms, with or
without modification, is permitted pursuant to, and subject
to the license terms contained in, the Revised BSD License
set forth in Section 4.c of the IETF Trust's Legal Provisions
Relating to IETF Documents
(https://trustee.ietf.org/license-info).

This version of this YANG module is part of RFC XXXX; see
the RFC itself for full legal notices.
  """
  _pyangbind_elements = {}

  

