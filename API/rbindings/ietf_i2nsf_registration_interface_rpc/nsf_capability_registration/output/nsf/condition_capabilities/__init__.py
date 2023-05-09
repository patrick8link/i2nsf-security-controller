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

from . import generic_nsf_capabilities
from . import advanced_nsf_capabilities
from . import context_capabilities
class condition_capabilities(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc/nsf-capability-registration/output/nsf/condition-capabilities. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Conditions capabilities.
  """
  __slots__ = ('_path_helper', '_extmethods', '__generic_nsf_capabilities','__advanced_nsf_capabilities','__context_capabilities',)

  _yang_name = 'condition-capabilities'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__generic_nsf_capabilities = YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    self.__advanced_nsf_capabilities = YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    self.__context_capabilities = YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)

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
      return ['ietf_i2nsf_registration_interface_rpc', 'nsf-capability-registration', 'output', 'nsf', 'condition-capabilities']

  def _get_generic_nsf_capabilities(self):
    """
    Getter method for generic_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/generic_nsf_capabilities (container)

    YANG Description: Conditions capabilities.
If a network security function has the condition
capabilities, the network security function
supports rule execution according to conditions of
IPv4, IPv6, TCP, UDP, SCTP, DCCP, ICMP, or ICMPv6.
    """
    return self.__generic_nsf_capabilities
      
  def _set_generic_nsf_capabilities(self, v, load=False):
    """
    Setter method for generic_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/generic_nsf_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_generic_nsf_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_generic_nsf_capabilities() directly.

    YANG Description: Conditions capabilities.
If a network security function has the condition
capabilities, the network security function
supports rule execution according to conditions of
IPv4, IPv6, TCP, UDP, SCTP, DCCP, ICMP, or ICMPv6.
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """generic_nsf_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__generic_nsf_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_generic_nsf_capabilities(self):
    self.__generic_nsf_capabilities = YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)


  def _get_advanced_nsf_capabilities(self):
    """
    Getter method for advanced_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/advanced_nsf_capabilities (container)

    YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
    """
    return self.__advanced_nsf_capabilities
      
  def _set_advanced_nsf_capabilities(self, v, load=False):
    """
    Setter method for advanced_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/advanced_nsf_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_advanced_nsf_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_advanced_nsf_capabilities() directly.

    YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """advanced_nsf_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__advanced_nsf_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_advanced_nsf_capabilities(self):
    self.__advanced_nsf_capabilities = YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)


  def _get_context_capabilities(self):
    """
    Getter method for context_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/context_capabilities (container)

    YANG Description: Security context capabilities
    """
    return self.__context_capabilities
      
  def _set_context_capabilities(self, v, load=False):
    """
    Setter method for context_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/context_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_context_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_context_capabilities() directly.

    YANG Description: Security context capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """context_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__context_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_context_capabilities(self):
    self.__context_capabilities = YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)

  generic_nsf_capabilities = __builtin__.property(_get_generic_nsf_capabilities, _set_generic_nsf_capabilities)
  advanced_nsf_capabilities = __builtin__.property(_get_advanced_nsf_capabilities, _set_advanced_nsf_capabilities)
  context_capabilities = __builtin__.property(_get_context_capabilities, _set_context_capabilities)


  _pyangbind_elements = OrderedDict([('generic_nsf_capabilities', generic_nsf_capabilities), ('advanced_nsf_capabilities', advanced_nsf_capabilities), ('context_capabilities', context_capabilities), ])


from . import generic_nsf_capabilities
from . import advanced_nsf_capabilities
from . import context_capabilities
class condition_capabilities(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc/nsf-capability-registration/output/nsf/condition-capabilities. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Conditions capabilities.
  """
  __slots__ = ('_path_helper', '_extmethods', '__generic_nsf_capabilities','__advanced_nsf_capabilities','__context_capabilities',)

  _yang_name = 'condition-capabilities'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__generic_nsf_capabilities = YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    self.__advanced_nsf_capabilities = YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    self.__context_capabilities = YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)

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
      return ['ietf_i2nsf_registration_interface_rpc', 'nsf-capability-registration', 'output', 'nsf', 'condition-capabilities']

  def _get_generic_nsf_capabilities(self):
    """
    Getter method for generic_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/generic_nsf_capabilities (container)

    YANG Description: Conditions capabilities.
If a network security function has the condition
capabilities, the network security function
supports rule execution according to conditions of
IPv4, IPv6, TCP, UDP, SCTP, DCCP, ICMP, or ICMPv6.
    """
    return self.__generic_nsf_capabilities
      
  def _set_generic_nsf_capabilities(self, v, load=False):
    """
    Setter method for generic_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/generic_nsf_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_generic_nsf_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_generic_nsf_capabilities() directly.

    YANG Description: Conditions capabilities.
If a network security function has the condition
capabilities, the network security function
supports rule execution according to conditions of
IPv4, IPv6, TCP, UDP, SCTP, DCCP, ICMP, or ICMPv6.
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """generic_nsf_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__generic_nsf_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_generic_nsf_capabilities(self):
    self.__generic_nsf_capabilities = YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)


  def _get_advanced_nsf_capabilities(self):
    """
    Getter method for advanced_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/advanced_nsf_capabilities (container)

    YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
    """
    return self.__advanced_nsf_capabilities
      
  def _set_advanced_nsf_capabilities(self, v, load=False):
    """
    Setter method for advanced_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/advanced_nsf_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_advanced_nsf_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_advanced_nsf_capabilities() directly.

    YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """advanced_nsf_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__advanced_nsf_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_advanced_nsf_capabilities(self):
    self.__advanced_nsf_capabilities = YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)


  def _get_context_capabilities(self):
    """
    Getter method for context_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/context_capabilities (container)

    YANG Description: Security context capabilities
    """
    return self.__context_capabilities
      
  def _set_context_capabilities(self, v, load=False):
    """
    Setter method for context_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/context_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_context_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_context_capabilities() directly.

    YANG Description: Security context capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """context_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__context_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_context_capabilities(self):
    self.__context_capabilities = YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)

  generic_nsf_capabilities = __builtin__.property(_get_generic_nsf_capabilities, _set_generic_nsf_capabilities)
  advanced_nsf_capabilities = __builtin__.property(_get_advanced_nsf_capabilities, _set_advanced_nsf_capabilities)
  context_capabilities = __builtin__.property(_get_context_capabilities, _set_context_capabilities)


  _pyangbind_elements = OrderedDict([('generic_nsf_capabilities', generic_nsf_capabilities), ('advanced_nsf_capabilities', advanced_nsf_capabilities), ('context_capabilities', context_capabilities), ])


from . import generic_nsf_capabilities
from . import advanced_nsf_capabilities
from . import context_capabilities
class condition_capabilities(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc/nsf-capability-registration/output/nsf/condition-capabilities. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Conditions capabilities.
  """
  __slots__ = ('_path_helper', '_extmethods', '__generic_nsf_capabilities','__advanced_nsf_capabilities','__context_capabilities',)

  _yang_name = 'condition-capabilities'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__generic_nsf_capabilities = YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    self.__advanced_nsf_capabilities = YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    self.__context_capabilities = YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)

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
      return ['ietf_i2nsf_registration_interface_rpc', 'nsf-capability-registration', 'output', 'nsf', 'condition-capabilities']

  def _get_generic_nsf_capabilities(self):
    """
    Getter method for generic_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/generic_nsf_capabilities (container)

    YANG Description: Conditions capabilities.
If a network security function has the condition
capabilities, the network security function
supports rule execution according to conditions of
IPv4, IPv6, TCP, UDP, SCTP, DCCP, ICMP, or ICMPv6.
    """
    return self.__generic_nsf_capabilities
      
  def _set_generic_nsf_capabilities(self, v, load=False):
    """
    Setter method for generic_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/generic_nsf_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_generic_nsf_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_generic_nsf_capabilities() directly.

    YANG Description: Conditions capabilities.
If a network security function has the condition
capabilities, the network security function
supports rule execution according to conditions of
IPv4, IPv6, TCP, UDP, SCTP, DCCP, ICMP, or ICMPv6.
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """generic_nsf_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__generic_nsf_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_generic_nsf_capabilities(self):
    self.__generic_nsf_capabilities = YANGDynClass(base=generic_nsf_capabilities.generic_nsf_capabilities, is_container='container', yang_name="generic-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)


  def _get_advanced_nsf_capabilities(self):
    """
    Getter method for advanced_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/advanced_nsf_capabilities (container)

    YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
    """
    return self.__advanced_nsf_capabilities
      
  def _set_advanced_nsf_capabilities(self, v, load=False):
    """
    Setter method for advanced_nsf_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/advanced_nsf_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_advanced_nsf_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_advanced_nsf_capabilities() directly.

    YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """advanced_nsf_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__advanced_nsf_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_advanced_nsf_capabilities(self):
    self.__advanced_nsf_capabilities = YANGDynClass(base=advanced_nsf_capabilities.advanced_nsf_capabilities, is_container='container', yang_name="advanced-nsf-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)


  def _get_context_capabilities(self):
    """
    Getter method for context_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/context_capabilities (container)

    YANG Description: Security context capabilities
    """
    return self.__context_capabilities
      
  def _set_context_capabilities(self, v, load=False):
    """
    Setter method for context_capabilities, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/condition_capabilities/context_capabilities (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_context_capabilities is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_context_capabilities() directly.

    YANG Description: Security context capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """context_capabilities must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)""",
        })

    self.__context_capabilities = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_context_capabilities(self):
    self.__context_capabilities = YANGDynClass(base=context_capabilities.context_capabilities, is_container='container', yang_name="context-capabilities", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='container', is_config=True)

  generic_nsf_capabilities = __builtin__.property(_get_generic_nsf_capabilities, _set_generic_nsf_capabilities)
  advanced_nsf_capabilities = __builtin__.property(_get_advanced_nsf_capabilities, _set_advanced_nsf_capabilities)
  context_capabilities = __builtin__.property(_get_context_capabilities, _set_context_capabilities)


  _pyangbind_elements = OrderedDict([('generic_nsf_capabilities', generic_nsf_capabilities), ('advanced_nsf_capabilities', advanced_nsf_capabilities), ('context_capabilities', context_capabilities), ])


