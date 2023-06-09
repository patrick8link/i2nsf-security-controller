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

from . import nsf_capability_registration
class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc. Each member element of
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
  __slots__ = ('_path_helper', '_extmethods', '__nsf_capability_registration',)

  _yang_name = 'ietf-i2nsf-registration-interface'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

    load = kwargs.pop("load", None)
    if args:
      if len(args) > 1:
        raise TypeError("cannot create a YANG container with >1 argument")
      all_attr = True
      for e in self._pyangbind_elements:
        if not hasattr(args[0], e):
          all_attr = False
          break
      if not all_attr:
        raise ValueError("Supplied object did not have the correct attributes")
      for e in self._pyangbind_elements:
        nobj = getattr(args[0], e)
        if nobj._changed() is False:
          continue
        setmethod = getattr(self, "_set_%s" % e)
        if load is None:
          setmethod(getattr(args[0], e))
        else:
          setmethod(getattr(args[0], e), load=load)

  def _path(self):
    if hasattr(self, "_parent"):
      return self._parent._path()+[self._yang_name]
    else:
      return ['ietf_i2nsf_registration_interface_rpc']

  def _get_nsf_capability_registration(self):
    """
    Getter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    return self.__nsf_capability_registration
      
  def _set_nsf_capability_registration(self, v, load=False):
    """
    Setter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_nsf_capability_registration is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_nsf_capability_registration() directly.

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """nsf_capability_registration must be of a type compatible with rpc""",
          'defined-type': "rpc",
          'generated-type': """YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)""",
        })

    self.__nsf_capability_registration = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_nsf_capability_registration(self):
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

  nsf_capability_registration = __builtin__.property(_get_nsf_capability_registration, _set_nsf_capability_registration)


  _pyangbind_elements = OrderedDict([('nsf_capability_registration', nsf_capability_registration), ])


from . import nsf_capability_registration
class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc. Each member element of
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
  __slots__ = ('_path_helper', '_extmethods', '__nsf_capability_registration',)

  _yang_name = 'ietf-i2nsf-registration-interface'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

    load = kwargs.pop("load", None)
    if args:
      if len(args) > 1:
        raise TypeError("cannot create a YANG container with >1 argument")
      all_attr = True
      for e in self._pyangbind_elements:
        if not hasattr(args[0], e):
          all_attr = False
          break
      if not all_attr:
        raise ValueError("Supplied object did not have the correct attributes")
      for e in self._pyangbind_elements:
        nobj = getattr(args[0], e)
        if nobj._changed() is False:
          continue
        setmethod = getattr(self, "_set_%s" % e)
        if load is None:
          setmethod(getattr(args[0], e))
        else:
          setmethod(getattr(args[0], e), load=load)

  def _path(self):
    if hasattr(self, "_parent"):
      return self._parent._path()+[self._yang_name]
    else:
      return ['ietf_i2nsf_registration_interface_rpc']

  def _get_nsf_capability_registration(self):
    """
    Getter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    return self.__nsf_capability_registration
      
  def _set_nsf_capability_registration(self, v, load=False):
    """
    Setter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_nsf_capability_registration is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_nsf_capability_registration() directly.

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """nsf_capability_registration must be of a type compatible with rpc""",
          'defined-type': "rpc",
          'generated-type': """YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)""",
        })

    self.__nsf_capability_registration = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_nsf_capability_registration(self):
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

  nsf_capability_registration = __builtin__.property(_get_nsf_capability_registration, _set_nsf_capability_registration)


  _pyangbind_elements = OrderedDict([('nsf_capability_registration', nsf_capability_registration), ])


from . import nsf_capability_registration
class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc. Each member element of
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
  __slots__ = ('_path_helper', '_extmethods', '__nsf_capability_registration',)

  _yang_name = 'ietf-i2nsf-registration-interface'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

    load = kwargs.pop("load", None)
    if args:
      if len(args) > 1:
        raise TypeError("cannot create a YANG container with >1 argument")
      all_attr = True
      for e in self._pyangbind_elements:
        if not hasattr(args[0], e):
          all_attr = False
          break
      if not all_attr:
        raise ValueError("Supplied object did not have the correct attributes")
      for e in self._pyangbind_elements:
        nobj = getattr(args[0], e)
        if nobj._changed() is False:
          continue
        setmethod = getattr(self, "_set_%s" % e)
        if load is None:
          setmethod(getattr(args[0], e))
        else:
          setmethod(getattr(args[0], e), load=load)

  def _path(self):
    if hasattr(self, "_parent"):
      return self._parent._path()+[self._yang_name]
    else:
      return ['ietf_i2nsf_registration_interface_rpc']

  def _get_nsf_capability_registration(self):
    """
    Getter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    return self.__nsf_capability_registration
      
  def _set_nsf_capability_registration(self, v, load=False):
    """
    Setter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_nsf_capability_registration is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_nsf_capability_registration() directly.

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """nsf_capability_registration must be of a type compatible with rpc""",
          'defined-type': "rpc",
          'generated-type': """YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)""",
        })

    self.__nsf_capability_registration = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_nsf_capability_registration(self):
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

  nsf_capability_registration = __builtin__.property(_get_nsf_capability_registration, _set_nsf_capability_registration)


  _pyangbind_elements = OrderedDict([('nsf_capability_registration', nsf_capability_registration), ])


from . import nsf_capability_registration
class ietf_i2nsf_registration_interface(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc. Each member element of
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
  __slots__ = ('_path_helper', '_extmethods', '__nsf_capability_registration',)

  _yang_name = 'ietf-i2nsf-registration-interface'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

    load = kwargs.pop("load", None)
    if args:
      if len(args) > 1:
        raise TypeError("cannot create a YANG container with >1 argument")
      all_attr = True
      for e in self._pyangbind_elements:
        if not hasattr(args[0], e):
          all_attr = False
          break
      if not all_attr:
        raise ValueError("Supplied object did not have the correct attributes")
      for e in self._pyangbind_elements:
        nobj = getattr(args[0], e)
        if nobj._changed() is False:
          continue
        setmethod = getattr(self, "_set_%s" % e)
        if load is None:
          setmethod(getattr(args[0], e))
        else:
          setmethod(getattr(args[0], e), load=load)

  def _path(self):
    if hasattr(self, "_parent"):
      return self._parent._path()+[self._yang_name]
    else:
      return ['ietf_i2nsf_registration_interface_rpc']

  def _get_nsf_capability_registration(self):
    """
    Getter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    return self.__nsf_capability_registration
      
  def _set_nsf_capability_registration(self, v, load=False):
    """
    Setter method for nsf_capability_registration, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration (rpc)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_nsf_capability_registration is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_nsf_capability_registration() directly.

    YANG Description: Description of the capabilities that the
Security Controller requests to the DMS
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """nsf_capability_registration must be of a type compatible with rpc""",
          'defined-type': "rpc",
          'generated-type': """YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)""",
        })

    self.__nsf_capability_registration = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_nsf_capability_registration(self):
    self.__nsf_capability_registration = YANGDynClass(base=nsf_capability_registration.nsf_capability_registration, is_leaf=True, yang_name="nsf-capability-registration", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='rpc', is_config=True)

  nsf_capability_registration = __builtin__.property(_get_nsf_capability_registration, _set_nsf_capability_registration)


  _pyangbind_elements = OrderedDict([('nsf_capability_registration', nsf_capability_registration), ])


