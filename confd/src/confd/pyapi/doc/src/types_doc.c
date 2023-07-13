/*
 * types documentation
 */

#define DOC(name) PyDoc_STRVAR(name ## __doc__,

/* ========================================================================= */
/*                                                                           */
/* Value                                                                     */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdValue)
/* ------------------------------------------------------------------------- */
"This type represents the c-type confd_value_t.\n\n"

"The contructor for this type has the following signature:\n\n"

"Value(init, type) -> object\n\n"

"If type is not provided it will be automatically set by inspecting the type\n"
"of argument init according to this table:\n\n"

"Python type      |  Value type\n"
"-----------------|------------\n"
"bool             |  C_BOOL\n"
"int              |  C_INT32\n"
"long             |  C_INT64\n"
"float            |  C_DOUBLE\n"
"string           |  C_BUF\n\n"

"If any other type is provided for the init argument, the type will be set to\n"
"C_BUF and the value will be the string representation of init.\n\n"

"For types C_XMLTAG, C_XMLBEGIN and C_XMLEND the init argument must be a\n"
"2-tuple which specifies the ns and tag values like this: (ns, tag).\n\n"

"For type C_IDENTITYREF the init argument must be a\n"
"2-tuple which specifies the ns and id values like this: (ns, id).\n\n"

"For types C_IPV4, C_IPV6, C_DATETIME, C_DATE, C_TIME, C_DURATION, C_OID,\n"
"C_IPV4PREFIX and C_IPV6PREFIX, the init argument must be a string.\n\n"

"For type C_DECIMAL64 the init argument must be a string, or a 2-tuple which\n"
"specifies value and fraction digits like this: (value, fraction_digits).\n\n"

"For type C_BINARY the init argument must be a bytes instance.\n\n"

"Keyword arguments:\n\n"

"* init -- the initial value\n"
"* type -- type (optional, see confd_types(3))"
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_confd_type)
/* ------------------------------------------------------------------------- */
"confd_type() -> int\n\n"

"Returns the confd type."
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_confd_type_str)
/* ------------------------------------------------------------------------- */
"confd_type_str() -> str\n\n"

"Returns a string representation for the Value type."
);

/* ------------------------------------------------------------------------- */
DOC(confdValue__size)
/* ------------------------------------------------------------------------- */
"_size() -> long\n\n"

"Returns the size of the value."
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_as_xmltag)
/* ------------------------------------------------------------------------- */
"as_xmltag() -> XmlTag\n\n"

"Returns a XmlTag instance if this value is of type C_XMLTAG."
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_as_decimal64)
/* ------------------------------------------------------------------------- */
"as_decimal64() -> Tuple[int, int]\n\n"

"Returns a tuple containing (value, fraction_digits) if this value is of\n"
"type C_DECIMAL64."
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_as_list)
/* ------------------------------------------------------------------------- */
"as_list() -> list\n\n"

"Returns a list of Value's if this value is of type C_LIST."
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_as_pyval)
/* ------------------------------------------------------------------------- */
"as_pyval() -> Any\n\n"

"Tries to convert a Value to a native Python type. If possible the object\n"
"returned will be of the same type as used when initializing a Value object.\n"
"If the type cannot be represented as something useful in Python a string\n"
"will be returned. Note that not all Value types are supported.\n\n"

"E.g. assuming you already have a value object, this should be possible\n"
"in most cases:\n\n"

"  newvalue = Value(value.as_pyval(), value.confd_type())"
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_str2val)
/* ------------------------------------------------------------------------- */
"str2val(value, schema_type) -> Value\n"
"(class method)\n\n"

"Create and return a Value from a string. The schema_type argument must be\n"
"either a 2-tuple with namespace and keypath, a CsNode instance or a CsType\n"
"instance.\n\n"

"Keyword arguments:\n\n"

"* value -- string value\n"
"* schema_type -- either (ns, keypath), a CsNode or a CsType"
);

/* ------------------------------------------------------------------------- */
DOC(confdValue_val2str)
/* ------------------------------------------------------------------------- */
"val2str(schema_type) -> str\n\n"

"Return a string representation of Value. The schema_type argument must be\n"
"either a 2-tuple with namespace and keypath, a CsNode instance or a CsType\n"
"instance.\n\n"

"Keyword arguments:\n\n"

"* schema_type -- either (ns, keypath), a CsNode or a CsType"
);

/* ========================================================================= */
/*                                                                           */
/* TagValue                                                                  */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdTagValue)
/* ------------------------------------------------------------------------- */
"This type represents the c-type confd_tag_value_t.\n\n"

"In addition to the 'ns' and 'tag' attributes there is an additional\n"
"attribute 'v' which containes the Value object.\n\n"

"The contructor for this type has the following signature:\n\n"

"TagValue(xmltag, v, tag, ns) -> object\n\n"

"There are two ways to contruct this object. The first one requires that both\n"
"xmltag and v are specified. The second one requires that both tag and ns are\n"
"specified.\n\n"

"Keyword arguments:\n\n"

"* xmltag -- a XmlTag instance (optional)\n"
"* v -- a Value instance (optional)\n"
"* tag -- tag hash (optional)\n"
"* ns -- namespace hash (optional)"
);

/* ------------------------------------------------------------------------- */
DOC(confdTagValue_attr_ns)
/* ------------------------------------------------------------------------- */
"namespace hash"
);

/* ------------------------------------------------------------------------- */
DOC(confdTagValue_attr_tag)
/* ------------------------------------------------------------------------- */
"tag hash"
);

/* ========================================================================= */
/*                                                                           */
/* AttrValue                                                                 */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdAttrValue)
/* ------------------------------------------------------------------------- */
"This type represents the c-type confd_attr_value_t.\n\n"

"The contructor for this type has the following signature:\n\n"

"AttrValue(attr, v) -> object\n\n"

"Keyword arguments:\n\n"

"* attr -- attribute type\n"
"* v -- value\n\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdAttrValue_attr_attr)
/* ------------------------------------------------------------------------- */
"attribute type (int)"
);

/* ------------------------------------------------------------------------- */
DOC(confdAttrValue_attr_v)
/* ------------------------------------------------------------------------- */
"attribute value (Value)"
);

/* ========================================================================= */
/*                                                                           */
/* XmlTag                                                                    */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdXmlTag)
/* ------------------------------------------------------------------------- */
"This type represent the c-type struct xml_tag.\n\n"

"The contructor for this type has the following signature:\n\n"

"XmlTag(ns, tag) -> object\n\n"

"Keyword arguments:\n\n"

"* ns -- namespace hash\n"
"* tag -- tag hash"
);

/* ------------------------------------------------------------------------- */
DOC(confdXmlTag_attr_ns)
/* ------------------------------------------------------------------------- */
"namespace hash value (unsigned int)"
);

/* ------------------------------------------------------------------------- */
DOC(confdXmlTag_attr_tag)
/* ------------------------------------------------------------------------- */
"tag hash value (unsigned int)"
);

/* ========================================================================= */
/*                                                                           */
/* HKeypathRef                                                               */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdHKeypathRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type confd_hkeypath_t.\n\n"

"HKeypathRef implements some sequence methods which enables indexing,\n"
"iteration and length checking. There is also support for slicing, e.g:\n\n"

"Lets say the variable hkp is a valid hkeypath pointing to '/foo/bar{a}/baz'\n"
"and we slice that object like this:\n\n"

"    newhkp = hkp[1:]\n\n"

"In this case newhkp will be a new hkeypath pointing to '/foo/bar{a}'.\n"
"Note that the last element must always be included, so trying to create\n"
"a slice with hkp[1:2] will fail.\n\n"

"The example above could also be written using the dup_len() method:\n\n"

"    newhkp = hkp.dup_len(3)\n\n"

"Retrieving an element of the HKeypathRef when the underlying Value is of\n"
"type C_XMLTAG returns a XmlTag instance. In all other cases a tuple of\n"
"Values is returned.\n\n"

"When receiving an HKeypathRef object as on argument in a callback method,\n"
"the underlying object is only borrowed, so this particular instance is only\n"
"valid inside that callback method. If one, for some reason, would like\n"
"to keep the HKeypathRef object 'alive' for any longer than that, use\n"
"dup() or dup_len() to get a copy of it. Slicing also creates a copy.\n\n"

"HKeypathRef cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdHKeypathRef_dup)
/* ------------------------------------------------------------------------- */
"dup() -> HKeypathRef\n\n"

"Duplicates this hkeypath.\n\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdHKeypathRef_dup_len)
/* ------------------------------------------------------------------------- */
"dup_len(len) -> HKeypathRef\n\n"

"Duplicates the first len elements of this hkeypath.\n\n"

"Keyword arguments:\n\n"

"* len -- number of elements to include in the copy"
);

/* ========================================================================= */
/*                                                                           */
/* TransCtxRef                                                               */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdTransCtxRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_trans_ctx.\n\n"

"Available attributes:\n\n"

"* fd -- worker socket (int)\n"
"* th -- transaction handle (int)\n"
"* secondary_index -- secondary index number for list traversal (int)\n"
"* username -- from user session (string) DEPRECATED, see uinfo\n"
"* context -- from user session (string) DEPRECATED, see uinfo\n"
"* uinfo -- user session (UserInfo)\n"
"* accumulated -- if the data provider is using the accumulate functionality\n"
"                 this attribute will contain the first dp.TrItemRef object\n"
"                 in the linked list, otherwise if will be None\n"
"* traversal_id -- unique id for the get_next* invocation\n\n"

"TransCtxRef cannot be directly instantiated from Python."
);

/* ========================================================================= */
/*                                                                           */
/* TrItemRef                                                                 */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdTrItemRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type confd_tr_item.\n\n"

"Available attributes:\n\n"

"* callpoint -- the callpoint (string)\n"
"* op -- operation, one of C_SET_ELEM, C_CREATE, C_REMOVE, C_SET_CASE,\n"
"        C_SET_ATTR or C_MOVE_AFTER (int)\n"
"* hkp -- the keypath (HKeypathRef)\n"
"* val -- the value (Value or None)\n"
"* choice -- the choice, only for C_SET_CASE (Value or None)\n"
"* attr -- attribute, only for C_SET_ATTR (int or None)\n"
"* next -- the next TrItemRef object in the linked list or None if no more\n"
"          items are found\n\n"

"TrItemRef cannot be directly instantiated from Python."
);

/* ========================================================================= */
/*                                                                           */
/* DbCtxRef                                                                  */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdDbCtxRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_db_ctx.\n\n"

"DbCtxRef cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdDbCtxRef_dx)
/* ------------------------------------------------------------------------- */
"dx() -> DaemonCtxRef"
);

/* ------------------------------------------------------------------------- */
DOC(confdDbCtxRef_lastop)
/* ------------------------------------------------------------------------- */
"lastop() -> int"
);

/* ------------------------------------------------------------------------- */
DOC(confdDbCtxRef_did)
/* ------------------------------------------------------------------------- */
"did() -> int"
);

/* ------------------------------------------------------------------------- */
DOC(confdDbCtxRef_qref)
/* ------------------------------------------------------------------------- */
"qref() -> int"
);

/* ------------------------------------------------------------------------- */
DOC(confdDbCtxRef_uinfo)
/* ------------------------------------------------------------------------- */
"uinfo() -> " CONFD_PY_MODULE ".UserInfo"
);

/* ========================================================================= */
/*                                                                           */
/* UserInfo                                                                  */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_user_info.\n\n"

"UserInfo cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_username)
/* ------------------------------------------------------------------------- */
"username -- the username (string)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_usid)
/* ------------------------------------------------------------------------- */
"usid -- user session id (int)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_context)
/* ------------------------------------------------------------------------- */
"context -- the context (string)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_af)
/* ------------------------------------------------------------------------- */
"af -- address family AF_INIT or AF_INET6 (int)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_addr)
/* ------------------------------------------------------------------------- */
"addr -- ip address (string)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_snmp_v3_ctx)
/* ------------------------------------------------------------------------- */
"snmp_v3_ctx -- SNMP context (string)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_clearpass)
/* ------------------------------------------------------------------------- */
"clearpass -- password if available (string)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_logintime)
/* ------------------------------------------------------------------------- */
"logintime -- time for login (long)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_proto)
/* ------------------------------------------------------------------------- */
"proto -- protocol (int)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_port)
/* ------------------------------------------------------------------------- */
"port -- source port (int)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_lmode)
/* ------------------------------------------------------------------------- */
"lmode -- the lock we have (int)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_flags)
/* ------------------------------------------------------------------------- */
"flags -- CONFD_USESS_FLAG_... (int)\n"
);

/* ------------------------------------------------------------------------- */
DOC(confdUserInfo_attr_actx_thandle)
/* ------------------------------------------------------------------------- */
"actx_thandle -- action context transaction handle\n\n"
);

/* ========================================================================= */
/*                                                                           */
/* AuthorizationInfo                                                         */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdAuthorizationInfo)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_authorization_info.\n\n"

"AuthorizationInfo cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdAuthorizationInfo_attr_groups)
/* ------------------------------------------------------------------------- */
"authorization groups (list of strings)"
);

/* ========================================================================= */
/*                                                                           */
/* AuthCtxRef                                                                */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdAuthCtxRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_auth_ctx.\n\n"

"Available attributes:\n\n"

"* uinfo -- the user info (UserInfo)\n"
"* method -- the method (string)\n"
"* success -- success or failure (bool)\n"
"* groups -- authorization groups if success is True (list of strings)\n"
"* logno -- log number if success is False (int)\n"
"* reason -- error reason if success is False (string)\n\n"

"AuthCtxRef cannot be directly instantiated from Python."
);

/* ========================================================================= */
/*                                                                           */
/* AuthorizationCtxRef                                                       */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdAuthorizationCtxRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_authorization_ctx.\n\n"

"Available attributes:\n\n"

"* uinfo -- the user info (UserInfo) or None\n"
"* groups -- authorization groups (list of strings) or None\n\n"

"AuthorizationCtxRef cannot be directly instantiated from Python."
);

/* ========================================================================= */
/*                                                                           */
/* NotificationCtxRef                                                        */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdNotificationCtxRef)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_notification_ctx.\n\n"

"Available attributes:\n\n"

"* name -- stream name or snmp notify name (string or None)\n"
"* ctx_name -- for snmp only (string or None)\n"
"* fd -- worker socket (int)\n"
"* dx -- the daemon context (DaemonCtxRef)\n\n"

"NotificationCtxRef cannot be directly instantiated from Python."
);

/* ========================================================================= */
/*                                                                           */
/* NotificationsData                                                         */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdNotificationsData)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_notifications_data.\n\n"

"The contructor for this type has the following signature:\n\n"

"NotificationsData(hearbeat_interval, health_check_interval, stream_name,\n"
"                  start_time, stop_time, xpath_filter, usid,\n"
"                  verbosity) -> object\n\n"

"Keyword arguments:\n\n"

"* heartbeat_interval -- time in milli seconds (int)\n"
"* health_check_interval -- time in milli seconds (int)\n"
"* stream_name -- name of the notification stream (string)\n"
"* start_time -- the start time (Value)\n"
"* stop_time -- the stop time (Value)\n"
"* xpath_filter -- XPath filter for the stream (string) - optional\n"
"* usid -- user session id for AAA restriction (int) - optional\n"
"* verbosity -- progress verbosity level (int) - optional"
);

/* ========================================================================= */
/*                                                                           */
/* Notification                                                              */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdNotification)
/* ------------------------------------------------------------------------- */
"This is a placeholder for the c-type struct confd_notification.\n\n"

"Notification cannot be directly instantiated from Python."
);

/* ========================================================================= */
/*                                                                           */
/* DateTime                                                                  */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdDateTime)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_datetime.\n\n"

"The contructor for this type has the following signature:\n\n"

"DateTime(year, month, day, hour, min, sec, micro, timezone,\n"
"         timezone_minutes) -> object\n\n"

"Keyword arguments:\n\n"

"* year -- the year (int)\n"
"* month -- the month (int)\n"
"* day -- the day (int)\n"
"* hour -- the hour (int)\n"
"* min -- minutes (int)\n"
"* sec -- seconds (int)\n"
"* micro -- micro seconds (int)\n"
"* timezone -- the timezone (int)\n"
"* timezone_minutes -- number of timezone_minutes (int)"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_year)
/* ------------------------------------------------------------------------- */
"the year"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_month)
/* ------------------------------------------------------------------------- */
"the month"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_day)
/* ------------------------------------------------------------------------- */
"the day"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_hour)
/* ------------------------------------------------------------------------- */
"the hour"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_min)
/* ------------------------------------------------------------------------- */
"minutes"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_sec)
/* ------------------------------------------------------------------------- */
"seconds"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_micro)
/* ------------------------------------------------------------------------- */
"micro seconds"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_timezone)
/* ------------------------------------------------------------------------- */
"timezone"
);

/* ------------------------------------------------------------------------- */
DOC(confdDateTime_attr_timezone_minutes)
/* ------------------------------------------------------------------------- */
"timezone minutes"
);

/* ========================================================================= */
/*                                                                           */
/* SnmpVarbind                                                               */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdSnmpVarbind)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_snmp_varbind.\n\n"

"The contructor for this type has the following signature:\n\n"

"SnmpVarbind(type, val, vartype, name, oid, cr) -> object\n\n"

"Keyword arguments:\n\n"

"* type -- SNMP_VARIABLE, SNMP_OID or SNMP_COL_ROW (int)\n"
"* val -- value (Value)\n"
"* vartype -- snmp type (optional)\n"
"* name -- mandatory if type is SNMP_VARIABLE (string)\n"
"* oid -- mandatory if type is SNMP_OID (list of integers)\n"
"* cr -- mandatory if type is SNMP_COL_ROW (described below)\n\n"

"When type is SNMP_COL_ROW the cr argument must be provided. It is built up\n"
"as a 2-tuple like this: tuple(string, list(int)).\n\n"

"The first element of the 2-tuple is the column name.\n\n"
"The second element (the row index) is a list of up to 128 integers."
);

/* ------------------------------------------------------------------------- */
DOC(confdSnmpVarbind_attr_type)
/* ------------------------------------------------------------------------- */
"the SnmpVarbind type"
);

/* ========================================================================= */
/*                                                                           */
/* MaapiRollback                                                             */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(maapiRollback)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct maapi_rollback.\n\n"

"MaapRollback cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_nr)
/* ------------------------------------------------------------------------- */
"the nr attribute (int)"
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_creator)
/* ------------------------------------------------------------------------- */
"the creator (string)"
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_datestr)
/* ------------------------------------------------------------------------- */
"the date (string)"
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_via)
/* ------------------------------------------------------------------------- */
"the via (string)"
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_fixed_nr)
/* ------------------------------------------------------------------------- */
"the fixed_nr (int)"
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_label)
/* ------------------------------------------------------------------------- */
"the label (string)"
);

/* ------------------------------------------------------------------------- */
DOC(maapiRollback_attr_comment)
/* ------------------------------------------------------------------------- */
"the comment (string)"
);

/* ========================================================================= */
/*                                                                           */
/* QueryResult                                                               */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(queryResult)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_query_result.\n\n"

"QueryResult implements some sequence methods which enables indexing,\n"
"iteration and length checking.\n\n"

"QueryResult cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(queryResult_attr_type)
/* ------------------------------------------------------------------------- */
"the query result type (int)"
);

/* ------------------------------------------------------------------------- */
DOC(queryResult_attr_offset)
/* ------------------------------------------------------------------------- */
"the offset (int)"
);

/* ------------------------------------------------------------------------- */
DOC(queryResult_attr_nresults)
/* ------------------------------------------------------------------------- */
"number of results (int)"
);

/* ------------------------------------------------------------------------- */
DOC(queryResult_attr_nelements)
/* ------------------------------------------------------------------------- */
"number of elements (int)"
);

/* ========================================================================= */
/*                                                                           */
/* CsNode                                                                    */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdCsNode)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_cs_node.\n\n"

"CsNode cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_ns)
/* ------------------------------------------------------------------------- */
"ns() -> int\n\n"

"Returns the namespace value."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_tag)
/* ------------------------------------------------------------------------- */
"tag() -> int\n\n"

"Returns the tag value."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_parent)
/* ------------------------------------------------------------------------- */
"parent() -> Union[CsNode, None]\n\n"

"Returns the parent CsNode or None."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_children)
/* ------------------------------------------------------------------------- */
"children() -> Union[CsNode, None]\n\n"

"Returns the children CsNode or None."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_next)
/* ------------------------------------------------------------------------- */
"next() -> Union[CsNode, None]\n\n"

"Returns the next CsNode or None."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_info)
/* ------------------------------------------------------------------------- */
"info() -> CsNodeInfo\n\n"

"Returns a CsNodeInfo."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_action)
/* ------------------------------------------------------------------------- */
"is_action() -> bool\n\n"

"Returns True if CsNode is an action."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_case)
/* ------------------------------------------------------------------------- */
"is_case() -> bool\n\n"

"Returns True if CsNode is a case."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_container)
/* ------------------------------------------------------------------------- */
"is_container() -> bool\n\n"

"Returns True if CsNode is a container."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_p_container)
/* ------------------------------------------------------------------------- */
"is_p_container() -> bool\n\n"

"Returns True if CsNode is a presence container."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_np_container)
/* ------------------------------------------------------------------------- */
"is_np_container() -> bool\n\n"

"Returns True if CsNode is a non presence container."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_empty_leaf)
/* ------------------------------------------------------------------------- */
"is_empty_leaf() -> bool\n\n"

"Returns True if CsNode is a leaf which is empty."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_non_empty_leaf)
/* ------------------------------------------------------------------------- */
"is_non_empty_leaf() -> bool\n\n"

"Returns True if CsNode is a leaf which is not of type empty."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_leaf)
/* ------------------------------------------------------------------------- */
"is_leaf() -> bool\n\n"

"Returns True if CsNode is a leaf."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_leaf_list)
/* ------------------------------------------------------------------------- */
"is_leaf_list() -> bool\n\n"

"Returns True if CsNode is a leaf-list."
);
/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_key)
/* ------------------------------------------------------------------------- */
"is_key() -> bool\n\n"

"Returns True if CsNode is a key."
);
/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_list)
/* ------------------------------------------------------------------------- */
"is_list() -> bool\n\n"

"Returns True if CsNode is a list."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_action_param)
/* ------------------------------------------------------------------------- */
"is_action_param() -> bool\n\n"

"Returns True if CsNode is an action parameter."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_action_result)
/* ------------------------------------------------------------------------- */
"is_action_result() -> bool\n\n"

"Returns True if CsNode is an action result."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_writable)
/* ------------------------------------------------------------------------- */
"is_writable() -> bool\n\n"

"Returns True if CsNode is writable."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_notif)
/* ------------------------------------------------------------------------- */
"is_notif() -> bool\n\n"

"Returns True if CsNode is a notification."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_oper)
/* ------------------------------------------------------------------------- */
"is_oper() -> bool\n\n"

"Returns True if CsNode is OPER data."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_has_when)
/* ------------------------------------------------------------------------- */
"has_when() -> bool\n\n"

"Returns True if CsNode has YANG 'when' statement(s)."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_has_display_when)
/* ------------------------------------------------------------------------- */
"has_display_when() -> bool\n\n"

"Returns True if CsNode has YANG 'tailf:display-when' statement(s)."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_leafref)
/* ------------------------------------------------------------------------- */
"is_leafref() -> bool\n\n"

"Returns True if CsNode is a YANG 'leafref'."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNode_is_mount_point)
/* ------------------------------------------------------------------------- */
"is_mount_point() -> bool\n\n"

"Returns True if CsNode is a mount point."
);

/* ========================================================================= */
/*                                                                           */
/* CsNodeInfo                                                                */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_cs_node_info.\n\n"

"CsNodeInfo cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_keys)
/* ------------------------------------------------------------------------- */
"keys() -> List[int]\n\n"

"Returns a list of hashed key values."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_min_occurs)
/* ------------------------------------------------------------------------- */
"min_occurs() -> int\n\n"

"Returns CsNodeInfo min_occurs."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_max_occurs)
/* ------------------------------------------------------------------------- */
"max_occurs() -> int\n\n"

"Returns CsNodeInfo max_occurs."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_shallow_type)
/* ------------------------------------------------------------------------- */
"shallow_type() -> int\n\n"

"Returns CsNodeInfo shallow_type."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_type)
/* ------------------------------------------------------------------------- */
"type() -> int\n\n"

"Returns CsNodeInfo type."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_defval)
/* ------------------------------------------------------------------------- */
"defval() -> Value\n\n"

"Returns CsNodeInfo value."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_choices)
/* ------------------------------------------------------------------------- */
"choices() -> Union[CsChoice, None]\n\n"

"Returns CsNodeInfo choices."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_flags)
/* ------------------------------------------------------------------------- */
"flags() -> int\n\n"

"Returns CsNodeInfo flags."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_cmp)
/* ------------------------------------------------------------------------- */
"cmp() -> int\n\n"

"Returns CsNodeInfo cmp."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsNodeInfo_meta_data)
/* ------------------------------------------------------------------------- */
"meta_data() -> Union[Dict, None]\n\n"

"Returns CsNodeInfo meta_data."
);

/* ========================================================================= */
/*                                                                           */
/* CsType                                                                    */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdCsType)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_type.\n\n"

"CsType cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsType_parent)
/* ------------------------------------------------------------------------- */
"parent() -> Union[CsType, None]\n\n"

"Returns the CsType parent."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsType_defval)
/* ------------------------------------------------------------------------- */
"defval() -> Union[CsType, None]\n\n"

"Returns the CsType defval."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsType_bitbig_size)
/* ------------------------------------------------------------------------- */
"bitbig_size() -> int\n\n"

"Returns the maximum size needed for the byte array for the BITBIG value\n"
"when a YANG bits type has a highest position above 63. If this is not a\n"
"BITBIG value or if the highest position is 63 or less, this function will\n"
"return 0."
);

/* ========================================================================= */
/*                                                                           */
/* CsChoice                                                                  */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_cs_choice.\n\n"

"CsChoice cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_ns)
/* ------------------------------------------------------------------------- */
"ns() -> int\n\n"

"Returns the CsChoice ns hash."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_tag)
/* ------------------------------------------------------------------------- */
"tag() -> int\n\n"

"Returns the CsChoice tag hash."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_min_occurs)
/* ------------------------------------------------------------------------- */
"min_occurs() -> int\n\n"

"Returns the CsChoice minOccurs."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_default_case)
/* ------------------------------------------------------------------------- */
"default_case() -> Union[CsCase, None]\n\n"

"Returns the CsChoice default case."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_parent)
/* ------------------------------------------------------------------------- */
"parent() -> Union[CsNode, None]\n\n"

"Returns the CsChoice parent CsNode."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_cases)
/* ------------------------------------------------------------------------- */
"cases() -> Union[CsCase, None]\n\n"

"Returns the CsChoice cases."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_next)
/* ------------------------------------------------------------------------- */
"next() -> Union[CsChoice, None]\n\n"

"Returns the CsChoice next."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsChoice_case_parent)
/* ------------------------------------------------------------------------- */
"case_parent() -> Union[CsCase, None]\n\n"

"Returns the CsChoice case parent."
);

/* ========================================================================= */
/*                                                                           */
/* CsCase                                                                  */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdCsCase)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_cs_case.\n\n"

"CsCase cannot be directly instantiated from Python."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsCase_ns)
/* ------------------------------------------------------------------------- */
"ns() -> int\n\n"

"Returns the CsCase ns hash."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsCase_tag)
/* ------------------------------------------------------------------------- */
"tag() -> int\n\n"

"Returns the CsCase tag hash."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsCase_first)
/* ------------------------------------------------------------------------- */
"first() -> Union[CsNode, None]\n\n"

"Returns the CsCase first."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsCase_last)
/* ------------------------------------------------------------------------- */
"last() -> Union[CsNode, None]\n\n"

"Returns the CsCase last."
);

DOC(confdCsCase_parent)
/* ------------------------------------------------------------------------- */
"parent() -> Union[CsChoice, None]\n\n"

"Returns the CsCase parent."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsCase_next)
/* ------------------------------------------------------------------------- */
"next() -> Union[CsCase, None]\n\n"

"Returns the CsCase next."
);

/* ------------------------------------------------------------------------- */
DOC(confdCsCase_choices)
/* ------------------------------------------------------------------------- */
"choices() -> Union[CsChoice, None]\n\n"

"Returns the CsCase choices."
);

/* ========================================================================= */
/*                                                                           */
/* ListFilter                                                                */
/*                                                                           */
/* ========================================================================= */

/* ------------------------------------------------------------------------- */
DOC(confdListFilter)
/* ------------------------------------------------------------------------- */
"This type represents the c-type struct confd_list_filter.\n\n"

"Available attributes:\n\n"

"* type -- filter type, LF_*\n"
"* expr1 -- OR, AND, NOT expression\n"
"* expr2 -- OR, AND expression\n"
"* op -- operation, CMP_* and EXEC_*\n"
"* node -- filter tagpath\n"
"* val -- filter value\n\n"

"ListFilter cannot be directly instantiated from Python."
);

#undef DOC
