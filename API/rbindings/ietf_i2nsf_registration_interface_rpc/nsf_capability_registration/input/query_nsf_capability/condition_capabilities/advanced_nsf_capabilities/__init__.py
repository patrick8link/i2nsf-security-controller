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

class advanced_nsf_capabilities(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module ietf-i2nsf-registration-interface - based on the path /ietf_i2nsf_registration_interface_rpc/nsf-capability-registration/input/query-nsf-capability/condition-capabilities/advanced-nsf-capabilities. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.

  YANG Description: Advanced Network Security Function (NSF) capabilities,
such as Anti-DDoS, IPS, and VoIP/VoCN.
This container contains the leaf-lists of advanced
NSF capabilities
  """
  __slots__ = ('_path_helper', '_extmethods', '__anti_ddos_capability','__ips_capability','__anti_virus_capability','__url_filtering_capability','__voip_vocn_filtering_capability',)

  _yang_name = 'advanced-nsf-capabilities'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__anti_ddos_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-ddos-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    self.__ips_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="ips-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    self.__anti_virus_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-virus-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    self.__url_filtering_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="url-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    self.__voip_vocn_filtering_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="voip-vocn-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)

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
      return ['ietf_i2nsf_registration_interface_rpc', 'nsf-capability-registration', 'input', 'query-nsf-capability', 'condition-capabilities', 'advanced-nsf-capabilities']

  def _get_anti_ddos_capability(self):
    """
    Getter method for anti_ddos_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/anti_ddos_capability (identityref)

    YANG Description: Anti-DDoS Attack capabilities
    """
    return self.__anti_ddos_capability
      
  def _set_anti_ddos_capability(self, v, load=False):
    """
    Setter method for anti_ddos_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/anti_ddos_capability (identityref)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_anti_ddos_capability is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_anti_ddos_capability() directly.

    YANG Description: Anti-DDoS Attack capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-ddos-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """anti_ddos_capability must be of a type compatible with identityref""",
          'defined-type': "ietf-i2nsf-registration-interface:identityref",
          'generated-type': """YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-ddos-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)""",
        })

    self.__anti_ddos_capability = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_anti_ddos_capability(self):
    self.__anti_ddos_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:packet-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:flow-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:byte-rate': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-ddos-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)


  def _get_ips_capability(self):
    """
    Getter method for ips_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/ips_capability (identityref)

    YANG Description: IPS capabilities
    """
    return self.__ips_capability
      
  def _set_ips_capability(self, v, load=False):
    """
    Setter method for ips_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/ips_capability (identityref)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_ips_capability is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_ips_capability() directly.

    YANG Description: IPS capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="ips-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """ips_capability must be of a type compatible with identityref""",
          'defined-type': "ietf-i2nsf-registration-interface:identityref",
          'generated-type': """YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="ips-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)""",
        })

    self.__ips_capability = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_ips_capability(self):
    self.__ips_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:signature-set': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-signature': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="ips-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)


  def _get_anti_virus_capability(self):
    """
    Getter method for anti_virus_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/anti_virus_capability (identityref)

    YANG Description: Antivirus capabilities
    """
    return self.__anti_virus_capability
      
  def _set_anti_virus_capability(self, v, load=False):
    """
    Setter method for anti_virus_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/anti_virus_capability (identityref)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_anti_virus_capability is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_anti_virus_capability() directly.

    YANG Description: Antivirus capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-virus-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """anti_virus_capability must be of a type compatible with identityref""",
          'defined-type': "ietf-i2nsf-registration-interface:identityref",
          'generated-type': """YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-virus-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)""",
        })

    self.__anti_virus_capability = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_anti_virus_capability(self):
    self.__anti_virus_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:detect': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:exception-files': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="anti-virus-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)


  def _get_url_filtering_capability(self):
    """
    Getter method for url_filtering_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/url_filtering_capability (identityref)

    YANG Description: URL Filtering capabilities
    """
    return self.__url_filtering_capability
      
  def _set_url_filtering_capability(self, v, load=False):
    """
    Setter method for url_filtering_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/url_filtering_capability (identityref)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_url_filtering_capability is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_url_filtering_capability() directly.

    YANG Description: URL Filtering capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="url-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """url_filtering_capability must be of a type compatible with identityref""",
          'defined-type': "ietf-i2nsf-registration-interface:identityref",
          'generated-type': """YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="url-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)""",
        })

    self.__url_filtering_capability = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_url_filtering_capability(self):
    self.__url_filtering_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:pre-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-defined': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="url-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)


  def _get_voip_vocn_filtering_capability(self):
    """
    Getter method for voip_vocn_filtering_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/voip_vocn_filtering_capability (identityref)

    YANG Description: VoIP/VoCN capabilities
    """
    return self.__voip_vocn_filtering_capability
      
  def _set_voip_vocn_filtering_capability(self, v, load=False):
    """
    Setter method for voip_vocn_filtering_capability, mapped from YANG variable /ietf_i2nsf_registration_interface_rpc/nsf_capability_registration/input/query_nsf_capability/condition_capabilities/advanced_nsf_capabilities/voip_vocn_filtering_capability (identityref)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_voip_vocn_filtering_capability is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_voip_vocn_filtering_capability() directly.

    YANG Description: VoIP/VoCN capabilities
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="voip-vocn-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """voip_vocn_filtering_capability must be of a type compatible with identityref""",
          'defined-type': "ietf-i2nsf-registration-interface:identityref",
          'generated-type': """YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="voip-vocn-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)""",
        })

    self.__voip_vocn_filtering_capability = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_voip_vocn_filtering_capability(self):
    self.__voip_vocn_filtering_capability = YANGDynClass(unique=True, base=TypedListType(allowed_type=RestrictedClassType(base_type=six.text_type, restriction_type="dict_key", restriction_arg={'call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:call-id': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}, 'i2nsfcap:user-agent': {'@module': 'ietf-i2nsf-capability', '@namespace': 'urn:ietf:params:xml:ns:yang:ietf-i2nsf-capability'}},)), is_leaf=False, yang_name="voip-vocn-filtering-capability", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=False, namespace='urn:ietf:params:xml:ns:yang:ietf-i2nsf-registration-interface', defining_module='ietf-i2nsf-registration-interface', yang_type='identityref', is_config=True)

  anti_ddos_capability = __builtin__.property(_get_anti_ddos_capability, _set_anti_ddos_capability)
  ips_capability = __builtin__.property(_get_ips_capability, _set_ips_capability)
  anti_virus_capability = __builtin__.property(_get_anti_virus_capability, _set_anti_virus_capability)
  url_filtering_capability = __builtin__.property(_get_url_filtering_capability, _set_url_filtering_capability)
  voip_vocn_filtering_capability = __builtin__.property(_get_voip_vocn_filtering_capability, _set_voip_vocn_filtering_capability)


  _pyangbind_elements = OrderedDict([('anti_ddos_capability', anti_ddos_capability), ('ips_capability', ips_capability), ('anti_virus_capability', anti_virus_capability), ('url_filtering_capability', url_filtering_capability), ('voip_vocn_filtering_capability', voip_vocn_filtering_capability), ])


