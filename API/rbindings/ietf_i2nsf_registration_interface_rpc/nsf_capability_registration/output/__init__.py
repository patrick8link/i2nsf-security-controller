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

from . import nsf
class output(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc/nsf-capability-registration/output. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.
  """
  __slots__ = ('_path_helper', '_extmethods', '__nsf',)

  _yang_name = 'output'
  _yang_namespace = 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__nsf = YANGDynClass(base=YANGListType("nsf_name",nsf.nsf, yang_name="nsf", parent=self, is_container='list', user_ordered=False, path_helper=self._path_helper, yang_keys='nsf-name', extensions=None), is_container='list', yang_name="nsf", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='list', is_config=True)

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
      return ['ietf_i2nsf_registration_interface_rpc', 'nsf-capability-registration', 'output']

  def _get_nsf(self):
    """
    Getter method for nsf, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf (list)

    YANG Description: The reply of the query to register the NSFs capabilities.
The capabilities requested in the input field can be covered
by multiple NSFs. This list consists of NSF(s) that cover
every capability specified in the input field.  The
selection method of which NSF(s) that should be listed in
the output field depends on the implementer.  If any of
the capabilities specified in the input field cannot be
covered by any NSF, the reply should return an <rpc-error>
with <error-message> of those capabilities.
    """
    return self.__nsf
      
  def _set_nsf(self, v, load=False):
    """
    Setter method for nsf, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/output/nsf (list)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_nsf is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_nsf() directly.

    YANG Description: The reply of the query to register the NSFs capabilities.
The capabilities requested in the input field can be covered
by multiple NSFs. This list consists of NSF(s) that cover
every capability specified in the input field.  The
selection method of which NSF(s) that should be listed in
the output field depends on the implementer.  If any of
the capabilities specified in the input field cannot be
covered by any NSF, the reply should return an <rpc-error>
with <error-message> of those capabilities.
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=YANGListType("nsf_name",nsf.nsf, yang_name="nsf", parent=self, is_container='list', user_ordered=False, path_helper=self._path_helper, yang_keys='nsf-name', extensions=None), is_container='list', yang_name="nsf", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='list', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """nsf must be of a type compatible with list""",
          'defined-type': "list",
          'generated-type': """YANGDynClass(base=YANGListType("nsf_name",nsf.nsf, yang_name="nsf", parent=self, is_container='list', user_ordered=False, path_helper=self._path_helper, yang_keys='nsf-name', extensions=None), is_container='list', yang_name="nsf", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='list', is_config=True)""",
        })

    self.__nsf = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_nsf(self):
    self.__nsf = YANGDynClass(base=YANGListType("nsf_name",nsf.nsf, yang_name="nsf", parent=self, is_container='list', user_ordered=False, path_helper=self._path_helper, yang_keys='nsf-name', extensions=None), is_container='list', yang_name="nsf", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, extensions=None, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='list', is_config=True)

  nsf = __builtin__.property(_get_nsf, _set_nsf)


  _pyangbind_elements = OrderedDict([('nsf', nsf), ])


