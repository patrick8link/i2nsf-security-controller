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

class bandwidth(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc/nsf-capability-registration/output/nsf/nsf-specification/bandwidth. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Network bandwidth available on an NSF
in the unit of Bps (Bytes per second).
  """
  __slots__ = ('_path_helper', '_extmethods', '__outbound','__inbound',)

  _yang_name = 'bandwidth'
  _yang_namespace = 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__outbound = YANGDynClass(base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="outbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)
    self.__inbound = YANGDynClass(base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="inbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)

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
      return ['ietf_i2nsf_registration_interface_rpc', 'nsf-capability-registration', 'output', 'nsf', 'nsf-specification', 'bandwidth']

  def _get_outbound(self):
    """
    Getter method for outbound, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/nsf_specification/bandwidth/outbound (uint64)

    YANG Description: The maximum aggregate outbound network bandwidth across all
interfaces available to the NSF in bytes per second (Bps).
    """
    return self.__outbound
      
  def _set_outbound(self, v, load=False):
    """
    Setter method for outbound, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/nsf_specification/bandwidth/outbound (uint64)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_outbound is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_outbound() directly.

    YANG Description: The maximum aggregate outbound network bandwidth across all
interfaces available to the NSF in bytes per second (Bps).
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="outbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """outbound must be of a type compatible with uint64""",
          'defined-type': "uint64",
          'generated-type': """YANGDynClass(base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="outbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)""",
        })

    self.__outbound = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_outbound(self):
    self.__outbound = YANGDynClass(base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="outbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)


  def _get_inbound(self):
    """
    Getter method for inbound, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/nsf_specification/bandwidth/inbound (uint64)

    YANG Description: The maximum aggregate inbound network bandwidth across all
interfaces available to the NSF in bytes per second (Bps).
    """
    return self.__inbound
      
  def _set_inbound(self, v, load=False):
    """
    Setter method for inbound, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf/nsf_specification/bandwidth/inbound (uint64)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_inbound is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_inbound() directly.

    YANG Description: The maximum aggregate inbound network bandwidth across all
interfaces available to the NSF in bytes per second (Bps).
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="inbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """inbound must be of a type compatible with uint64""",
          'defined-type': "uint64",
          'generated-type': """YANGDynClass(base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="inbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)""",
        })

    self.__inbound = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_inbound(self):
    self.__inbound = YANGDynClass(base=RestrictedClassType(base_type=long, restriction_dict={'range':  ['0..18446744073709551615']}, int_size=64), is_leaf=True, yang_name="inbound", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='uint64', is_config=True)

  outbound = __builtin__.property(_get_outbound, _set_outbound)
  inbound = __builtin__.property(_get_inbound, _set_inbound)


  _pyangbind_elements = OrderedDict([('outbound', outbound), ('inbound', inbound), ])


