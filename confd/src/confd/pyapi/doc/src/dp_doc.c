/*
 * dp documentation to be included in _dp.c
 */

#define DP_MODULE_DOCSTR(PROD) \
"Low level callback module for connecting data providers to " PROD ".\n\n"\
\
"This module is used to connect to the " PROD " Data Provider\n"\
"API. The purpose of this API is to provide callback hooks so that\n"\
"user-written data providers can provide data stored externally to " PROD \
".\n"\
PROD " needs this information in order to drive its northbound agents.\n\n"\
\
"The module is also used to populate items in the data model which are not\n"\
"data or configuration items, such as statistics items from the device.\n\n"\
\
"The module consists of a number of API functions whose purpose is to\n"\
"install different callback functions at different points in the data model\n"\
"tree which is the representation of the device configuration. Read more\n"\
"about callpoints in tailf_yang_extensions(5). Read more about how to use\n"\
"the module in the User Guide chapters on Operational data and External\n"\
"data.\n\n"\
\
"This documentation should be read together with the confd_lib_dp(3) man page."

#define DOC(name) PyDoc_STRVAR(_dp_ ## name ## __doc__,

/* ------------------------------------------------------------------------- */
DOC(init_daemon)
/* ------------------------------------------------------------------------- */
"init_daemon(name) -> DaemonCtxRef\n\n"

"Initializes and returns a new daemon context.\n\n"

"Keyword arguments:\n\n"

"* name -- a string used to uniquely identify the daemon"
);

/* ------------------------------------------------------------------------- */
DOC(release_daemon)
/* ------------------------------------------------------------------------- */
"release_daemon(dx) -> None\n\n"

"Releases all memory that has been allocated by init_daemon() and other\n"
"functions for the daemon context. The control socket as well as all the\n"
"worker sockets must be closed by the application (before or after\n"
"release_daemon() has been called).\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()"
);

/* ------------------------------------------------------------------------- */
DOC(set_daemon_flags)
/* ------------------------------------------------------------------------- */
"set_daemon_flags(dx, flags) -> None\n\n"

"Modifies the API behaviour according to the flags ORed into the flags\n"
"argument.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* flags -- the flags to set"
);

/* ------------------------------------------------------------------------- */
DOC(connect)
/* ------------------------------------------------------------------------- */
"connect(dx, sock, type, ip, port, path) -> None\n\n"

"Connects to the ConfD daemon. The socket instance provided via the 'sock'\n"
"argument must be kept alive during the lifetime of the daemon context.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* sock -- a Python socket instance\n"
"* type -- the socket type (CONTROL_SOCKET or WORKER_SOCKET)\n"
"* ip -- the ip address if socket is AF_INET (optional)\n"
"* port -- the port if socket is AF_INET (optional)\n"
"* path -- a filename if socket is AF_UNIX (optional)."
);

/* ------------------------------------------------------------------------- */
DOC(register_trans_cb)
/* ------------------------------------------------------------------------- */
"register_trans_cb(dx, trans) -> None\n\n"

"Registers transaction callback functions.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* trans -- the callback instance (see below)\n\n"

"The trans argument should be an instance of a class with callback methods.\n"

"E.g.:\n\n"

"    class TransCallbacks(object):\n"
"        def cb_init(self, tctx):\n"
"            pass\n\n"

"        def cb_trans_lock(self, tctx):\n"
"            pass\n\n"

"        def cb_trans_unlock(self, tctx):\n"
"            pass\n\n"

"        def cb_write_start(self, tctx):\n"
"            pass\n\n"

"        def cb_prepare(self, tctx):\n"
"            pass\n\n"

"        def cb_abort(self, tctx):\n"
"            pass\n\n"

"        def cb_commit(self, tctx):\n"
"            pass\n\n"

"        def cb_finish(self, tctx):\n"
"            pass\n\n"

"        def cb_interrupt(self, tctx):\n"
"            pass\n\n"

"    tcb = TransCallbacks()\n"
"    dp.register_trans_cb(dx, tcb)"
);

/* ------------------------------------------------------------------------- */
DOC(register_data_cb)
/* ------------------------------------------------------------------------- */
"register_data_cb(dx, callpoint, data, flags) -> None\n\n"

"Registers data manipulation callback functions.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* callpoint -- name of a tailf:callpoint in the data model\n"
"* data -- the callback instance (see below)\n"
"* flags -- data callbacks flags, dp.DATA_* (optional)\n\n"

"The data argument should be an instance of a class with callback methods.\n"

"E.g.:\n\n"

"    class DataCallbacks(object):\n"
"        def cb_exists_optional(self, tctx, kp):\n"
"            pass\n\n"

"        def cb_get_elem(self, tctx, kp):\n"
"            pass\n\n"

"        def cb_get_next(self, tctx, kp, next):\n"
"            pass\n\n"

"        def cb_set_elem(self, tctx, kp, newval):\n"
"            pass\n\n"

"        def cb_create(self, tctx, kp):\n"
"            pass\n\n"

"        def cb_remove(self, tctx, kp):\n"
"            pass\n\n"

"        def cb_find_next(self, tctx, kp, type, keys):\n"
"            pass\n\n"

"        def cb_num_instances(self, tctx, kp):\n"
"            pass\n\n"

"        def cb_get_object(self, tctx, kp):\n"
"            pass\n\n"

"        def cb_get_next_object(self, tctx, kp, next):\n"
"            pass\n\n"

"        def cb_find_next_object(self, tctx, kp, type, keys):\n"
"            pass\n\n"

"        def cb_get_case(self, tctx, kp, choice):\n"
"            pass\n\n"

"        def cb_set_case(self, tctx, kp, choice, caseval):\n"
"            pass\n\n"

"        def cb_get_attrs(self, tctx, kp, attrs):\n"
"            pass\n\n"

"        def cb_set_attr(self, tctx, kp, attr, v):\n"
"            pass\n\n"

"        def cb_move_after(self, tctx, kp, prevkeys):\n"
"            pass\n\n"

"        def cb_write_all(self, tctx, kp):\n"
"            pass\n\n"

"    dcb = DataCallbacks()\n"
"    dp.register_data_cb(dx, 'example-callpoint-1', dcb)"
);

/* ------------------------------------------------------------------------- */
DOC(register_range_data_cb)
/* ------------------------------------------------------------------------- */
"register_range_data_cb(dx, callpoint, data, lower, upper, path,\n"
"                       flags) -> None\n\n"

"This is a variant of register_data_cb() which registers a set of callbacks\n"
"for a range of list entries.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* callpoint -- name of a tailf:callpoint in the data model\n"
"* data -- the callback instance (see register_data_cb())\n"
"* lower -- a list of Value's or None\n"
"* upper -- a list of Value's or None\n"
"* path -- path for the list (string)\n"
"* flags -- data callbacks flags, dp.DATA_* (optional)"
);

/* ------------------------------------------------------------------------- */
DOC(register_done)
/* ------------------------------------------------------------------------- */
"register_done(dx) -> None\n\n"

"When we have registered all the callbacks for a daemon (including the other\n"
"types described below if we have them), we must call this function to\n"
"synchronize with ConfD. No callbacks will be invoked until it has been\n"
"called, and after the call, no further registrations are allowed.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()"
);

/* ------------------------------------------------------------------------- */
DOC(fd_ready)
/* ------------------------------------------------------------------------- */
"fd_ready(dx, sock) -> None\n\n"

"The database application owns all data provider sockets to ConfD and is\n"
"responsible for the polling of these sockets. When one of the ConfD\n"
"sockets has I/O ready to read, the application must invoke fd_ready() on\n"
"the socket.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* sock -- the socket"
);

/* ------------------------------------------------------------------------- */
DOC(trans_set_fd)
/* ------------------------------------------------------------------------- */
"trans_set_fd(tctx, sock) -> None\n\n"

"Associate a worker socket with the transaction, or validation phase. This\n"
"function must be called in the transaction and validation cb_init()\n"
"callbacks.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* sock -- a previously connected worker socket\n\n"

"A minimal implementation of a transaction cb_init() callback looks like:\n\n"

"    class TransCb(object):\n"
"        def __init__(self, workersock):\n"
"            self.workersock = workersock\n\n"

"        def cb_init(self, tctx):\n"
"            dp.trans_set_fd(tctx, self.workersock)"
);

/* ------------------------------------------------------------------------- */
DOC(trans_seterr)
/* ------------------------------------------------------------------------- */
"trans_seterr(tctx, errstr) -> None\n\n"

"This function is used by the application to set an error string.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(trans_seterr_extended)
/* ------------------------------------------------------------------------- */
"trans_seterr_extended(tctx, code, apptag_ns, apptag_tag, errstr) -> None\n\n"

"This function can be used to provide more structured error information\n"
"from a transaction or data callback.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(trans_seterr_extended_info)
/* ------------------------------------------------------------------------- */
"trans_seterr_extended_info(tctx, code, apptag_ns, apptag_tag,\n"
"                           error_info, errstr) -> None\n\n"

"This function can be used to provide structured error information in the\n"
"same way as trans_seterr_extended(), and additionally provide contents for\n"
"the NETCONF <error-info> element.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* error_info -- a list of _lib.TagValue instances\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(register_trans_validate_cb)
/* ------------------------------------------------------------------------- */
"register_trans_validate_cb(dx, vcbs) -> None\n\n"

"This function installs two callback functions for the daemon context. One\n"
"function that gets called when the validation phase starts in a transaction\n"
"and one when the validation phase stops in a transaction.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* vcbs -- the callback instance (see below)\n\n"


"The vcbs argument should be an instance of a class with callback methods.\n"

"E.g.:\n\n"

"    class TransValidateCallbacks(object):\n"
"        def cb_init(self, tctx):\n"
"            pass\n\n"

"        def cb_stop(self, tctx):\n"
"            pass\n\n"

"    vcbs = TransValidateCallbacks()\n"
"    dp.register_trans_validate_cb(dx, vcbs)"
);

/* ------------------------------------------------------------------------- */
DOC(register_valpoint_cb)
/* ------------------------------------------------------------------------- */
"register_valpoint_cb(dx, valpoint, vcb) -> None\n\n"

"We must also install an actual validation function for each validation\n"
"point, i.e. for each tailf:validate statement in the YANG data model.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* valpoint -- the name of the validation point\n"
"* vcb -- the callback instance (see below)\n\n"

"The vcb argument should be an instance of a class with a callback method.\n"

"E.g.:\n\n"

"    class ValpointCallback(object):\n"
"        def cb_validate(self, tctx, kp, newval):\n"
"            pass\n\n"

"    vcb = ValpointCallback()\n"
"    dp.register_valpoint_cb(dx, 'valpoint-1', vcb)"
);

/* ------------------------------------------------------------------------- */
DOC(register_range_valpoint_cb)
/* ------------------------------------------------------------------------- */
"register_range_valpoint_cb(dx, valpoint, vcb, lower, upper, path) -> None\n\n"

"A variant of register_valpoint_cb() which registers a validation function\n"
"for a range of key values. The lower, upper and path arguments are the same\n"
"as for register_range_data_cb().\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* valpoint -- name of a validation point\n"
"* data -- the callback instance (see register_valpoint_cb())\n"
"* lower -- a list of Value's or None\n"
"* upper -- a list of Value's or None\n"
"* path -- path for the list (string)"
);

/* ------------------------------------------------------------------------- */
DOC(register_action_cbs)
/* ------------------------------------------------------------------------- */
"register_action_cbs(dx, actionpoint, acb) -> None\n\n"

"This function registers up to five callback functions, two of which will\n"
"be called in sequence when an action is invoked.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* actionpoint -- the name of the action point\n"
"* vcb -- the callback instance (see below)\n\n"

"The acb argument should be an instance of a class with callback methods.\n"

"E.g.:\n\n"

"    class ActionCallbacks(object):\n"
"        def cb_init(self, uinfo):\n"
"            pass\n\n"

"        def cb_abort(self, uinfo):\n"
"            pass\n\n"

"        def cb_action(self, uinfo, name, kp, params):\n"
"            pass\n\n"

"        def cb_command(self, uinfo, path, argv):\n"
"            pass\n\n"

"        def cb_completion(self, uinfo, cli_style, token, completion_char,\n"
"                          kp, cmdpath, cmdparam_id, simpleType, extra):\n"
"            pass\n\n"

"    acb = ActionCallbacks()\n"
"    dp.register_action_cbs(dx, 'actionpoint-1', acb)\n\n"

"Notes about some of the callbacks:\n\n"

"cb_action()\n"
"    The params argument is a list of _lib.TagValue instances.\n\n"

"cb_command()\n"
"    The argv argument is a list of strings."
);

/* ------------------------------------------------------------------------- */
DOC(register_range_action_cbs)
/* ------------------------------------------------------------------------- */
"register_range_action_cbs(dx, actionpoint, acb, lower, upper, path) -> None"
"\n\n"

"A variant of register_action_cbs() which registers action callbacks for a\n"
"range of key values. The lower, upper, and path arguments are the same as\n"
"for register_range_data_cb().\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* actionpoint -- the name of the action point\n"
"* data -- the callback instance (see register_action_cbs())\n"
"* lower -- a list of Value's or None\n"
"* upper -- a list of Value's or None\n"
"* path -- path for the list (string)"
);

/* ------------------------------------------------------------------------- */
DOC(action_set_fd)
/* ------------------------------------------------------------------------- */
"action_set_fd(uinfo, sock) -> None\n\n"

"Associate a worker socket with the action. This function must be called in\n"
"the action cb_init() callback.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* sock -- a previously connected worker socket\n\n"

"A typical implementation of an action cb_init() callback looks like:\n\n"

"    class ActionCallbacks(object):\n"
"        def __init__(self, workersock):\n"
"            self.workersock = workersock\n\n"

"        def cb_init(self, uinfo):\n"
"            dp.action_set_fd(uinfo, self.workersock)"
);

/* ------------------------------------------------------------------------- */
DOC(action_reply_values)
/* ------------------------------------------------------------------------- */
"action_reply_values(uinfo, values) -> None\n\n"

"If the action definition specifies that the action should return data, it\n"
"must invoke this function in response to the cb_action() callback.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* values -- a list of _lib.TagValue instances or None"
);

/* ------------------------------------------------------------------------- */
DOC(action_reply_command)
/* ------------------------------------------------------------------------- */
"action_reply_command(uinfo, values) -> None\n\n"

"If a CLI callback command should return data, it must invoke this function\n"
"in response to the cb_command() callback.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* values -- a list of strings or None"
);

/* ------------------------------------------------------------------------- */
DOC(action_reply_rewrite)
/* ------------------------------------------------------------------------- */
"action_reply_rewrite(uinfo, values, unhides) -> None\n\n"

"This function can be called instead of action_reply_command() as a\n"
"response to a show path rewrite callback invocation.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* values -- a list of strings or None\n"
"* unhides -- a list of strings or None"
);

/* ------------------------------------------------------------------------- */
DOC(action_reply_rewrite2)
/* ------------------------------------------------------------------------- */
"action_reply_rewrite2(uinfo, values, unhides, selects) -> None\n\n"

"This function can be called instead of action_reply_command() as a\n"
"response to a show path rewrite callback invocation.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* values -- a list of strings or None\n"
"* unhides -- a list of strings or None\n"
"* selects -- a list of strings or None"
);

/* ------------------------------------------------------------------------- */
DOC(action_reply_completion)
/* ------------------------------------------------------------------------- */
"action_reply_completion(uinfo, values) -> None\n\n"

"This function must normally be called in response to the cb_completion()\n"
"callback.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* values -- a list of 3-tuples or None (see below)\n\n"

"The values argument must be None or a list of 3-tuples where each tuple is\n"
"built up like:\n\n"

"    (type::int, value::string, extra::string)\n\n"

"The third item of the tuple (extra) may be set to None."
);

/* ------------------------------------------------------------------------- */
DOC(action_reply_range_enum)
/* ------------------------------------------------------------------------- */
"action_reply_range_enum(uinfo, values, keysize) -> None\n\n"

"This function must be called in response to the cb_completion() callback\n"
"when it is invoked via a tailf:cli-custom-range-enumerator statement in the\n"
"data model.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* values -- a list of keys as strings or None\n"
"* keysize -- number of keys for the list in the data model\n\n"

"The values argument is a flat list of keys. If the list in the data model\n"
"specifies multiple keys this list is still flat. The keysize argument\n"
"tells us how many keys to use for each list element. So the size of values\n"
"should be a multiple of keysize."
);

/* ------------------------------------------------------------------------- */
DOC(action_delayed_reply_ok)
/* ------------------------------------------------------------------------- */
"action_delayed_reply_ok(uinfo) -> None\n\n"

"If we use the CONFD_DELAYED_RESPONSE as a return value from the action\n"
"callback, we must later asynchronously reply. This function is used to\n"
"reply with success.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context"
);

/* ------------------------------------------------------------------------- */
DOC(action_delayed_reply_error)
/* ------------------------------------------------------------------------- */
"action_delayed_reply_error(uinfo, errstr) -> None\n\n"

"If we use the CONFD_DELAYED_RESPONSE as a return value from the action\n"
"callback, we must later asynchronously reply. This function is used to\n"
"reply with error.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* errstr -- an error string"
);

/* ------------------------------------------------------------------------- */
DOC(action_seterr)
/* ------------------------------------------------------------------------- */
"action_seterr(uinfo, errstr) -> None\n\n"

"If action callback encounters fatal problems that can not be expressed via\n"
"the reply function, it may call this function with an appropriate message\n"
"and return CONFD_ERR instead of CONFD_OK.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(action_seterr_extended)
/* ------------------------------------------------------------------------- */
"action_seterr_extended(uninfo, code, apptag_ns, apptag_tag, errstr) -> None\n"
"\n"
"This function can be used to provide more structured error information\n"
"from an action callback.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(action_seterr_extended_info)
/* ------------------------------------------------------------------------- */
"action_seterr_extended_info(uinfo, code, apptag_ns, apptag_tag,\n"
"                            error_info, errstr) -> None\n\n"

"This function can be used to provide structured error information in the\n"
"same way as action_seterr_extended(), and additionally provide contents for\n"
"the NETCONF <error-info> element.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* error_info -- a list of _lib.TagValue instances\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(action_set_timeout)
/* ------------------------------------------------------------------------- */
"action_set_timeout(uinfo, timeout_secs) -> None\n\n"

"Some action callbacks may require a significantly longer execution time\n"
"than others, and this time may not even be possible to determine statically\n"
"(e.g. a file download). In such cases the /confdConfig/capi/queryTimeout\n"
"setting in confd.conf may be insufficient, and this function can be used to\n"
"extend (or shorten) the timeout for the current callback invocation. The\n"
"timeout is given in seconds from the point in time when the function is\n"
"called.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* timeout_secs -- timeout value"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_value)
/* ------------------------------------------------------------------------- */
"data_reply_value(tctx, v) -> None\n\n"

"This function is used to return a single data item to ConfD.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* v -- a _lib.Value instance"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_value_array)
/* ------------------------------------------------------------------------- */
"data_reply_value_array(tctx, vs) -> None\n\n"

"This function is used to return an array of values, corresponding to a\n"
"complete list entry, to ConfD. It can be used by the optional\n"
"cb_get_object() callback.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* vs -- a list of _lib.Value instances"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_tag_value_array)
/* ------------------------------------------------------------------------- */
"data_reply_tag_value_array(tctx, tvs) -> None\n\n"

"This function is used to return an array of values, corresponding to a\n"
"complete list entry, to ConfD. It can be used by the optional\n"
"cb_get_object() callback.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* tvs -- a list of _lib.TagValue instances or None"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_found)
/* ------------------------------------------------------------------------- */
"data_reply_found(tctx) -> None\n\n"

"This function is used by the cb_exists_optional() callback to indicate to\n"
"ConfD that a node does exist.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_not_found)
/* ------------------------------------------------------------------------- */
"data_reply_not_found(tctx) -> None\n\n"

"This function is used by the cb_get_elem() and cb_exists_optional()\n"
"callbacks to indicate to ConfD that a list entry or node does not exist.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_next_key)
/* ------------------------------------------------------------------------- */
"data_reply_next_key(tctx, keys, next) -> None\n\n"

"This function is used by the cb_get_next() and cb_find_next() callbacks to\n"
"return the next key.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* keys -- a list of keys of _lib.Value for a list item (se below)\n"
"* next -- int value passed to the next invocation of cb_get_next() callback\n"
"\n"
"A list may have mutiple key leafs specified in the data model. This is why\n"
"the keys argument must be a list."
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_next_object_array)
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */
"data_reply_next_object_array(tctx, v, next) -> None\n\n"

"This function is used by the optional cb_get_next_object() and\n"
"cb_find_next_object() callbacks to return an entire object including its keys."
"\n"
"It combines the functions of data_reply_next_key() and\n"
"data_reply_value_array().\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* v -- a list of _lib.Value instances\n"
"* next -- int value passed to the next invocation of cb_get_next() callback"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_next_object_arrays)
/* ------------------------------------------------------------------------- */
"data_reply_next_object_arrays(tctx, objs, timeout_millisecs) -> None\n\n"

"This function is used by the optional cb_get_next_object() and\n"
"cb_find_next_object() callbacks to return multiple objects including their\n"
"keys, in _lib.Value form.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* objs -- a list of tuples or None (see below)\n"
"* timeout_millisecs -- timeout value for ConfD's caching of returned data\n\n"

"The format of argument objs is list(tuple(list(_lib.Value), long)), or\n"
"None to indicate end of list. Another way to indicate end of list is to\n"
"include None as the first item in the 2-tuple last in the list.\n\n"

"E.g.:\n\n"

"    V = _lib.Value\n"
"    objs = [\n"
"             ( [ V(1), V(2) ], next1 ),\n"
"             ( [ V(3), V(4) ], next2 ),\n"
"             ( None, -1 )\n"
"           ]"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_next_object_tag_value_array)
/* ------------------------------------------------------------------------- */
"data_reply_next_object_tag_value_array(tctx, tvs, next) -> None\n\n"

"This function is used by the optional cb_get_next_object() and\n"
"cb_find_next_object() callbacks to return an entire object including its keys"
"\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* tvs -- a list of _lib.TagValue instances or None\n"
"* next -- int value passed to the next invocation of cb_get_next_object()\n"
"          callback\n\n"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_next_object_tag_value_arrays)
/* ------------------------------------------------------------------------- */
"data_reply_next_object_tag_value_arrays(tctx, objs, timeout_millisecs) -> None"
"\n\n"

"This function is used by the optional cb_get_next_object() and\n"
"cb_find_next_object() callbacks to return multiple objects including their\n"
"keys.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* objs -- a list of tuples or None (see below)\n"
"* timeout_millisecs -- timeout value for ConfD's caching of returned data\n\n"

"The format of argument objs is list(tuple(list(_lib.TagValue), long)) or\n"
"None to indicate end of list. Another way to indicate end of list is to\n"
"include None as the first item in the 2-tuple last in the list.\n\n"

"E.g.:\n\n"

"    objs = [\n"
"             ( [ tagval1, tagval2 ], next1 ),\n"
"             ( [ tagval3, tagval4, tagval5 ], next2 ),\n"
"             ( None, -1 )\n"
"           ]"
);

/* ------------------------------------------------------------------------- */
DOC(data_reply_attrs)
/* ------------------------------------------------------------------------- */
"data_reply_attrs(tctx, attrs) -> None\n\n"

"This function is used by the cb_get_attrs() callback to return the\n"
"requested attribute values.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* attrs -- a list of _lib.AttrValue instances"
);

/* ------------------------------------------------------------------------- */
DOC(data_set_timeout)
/* ------------------------------------------------------------------------- */
"data_set_timeout(tctx, timeout_secs) -> None\n\n"

"A data callback should normally complete quickly, since e.g. the\n"
"execution of a 'show' command in the CLI may require many data callback\n"
"invocations. In some rare cases it may still be necessary for a data\n"
"callback to have a longer execution time, and then this function can be\n"
"used to extend (or shorten) the timeout for the current callback invocation.\n"
"The timeout is given in seconds from the point in time when the function is\n"
"called.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* timeout_secs -- timeout value"
);

/* ------------------------------------------------------------------------- */
DOC(data_get_list_filter)
/* ------------------------------------------------------------------------- */
"data_get_list_filter(tctx) -> ListFilter\n\n"

"Get list filter from transaction context.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context"
);

/* ------------------------------------------------------------------------- */
DOC(delayed_reply_ok)
/* ------------------------------------------------------------------------- */
"delayed_reply_ok(tctx) -> None\n\n"

"This function must be used to return the equivalent of CONFD_OK when the\n"
"actual callback returned CONFD_DELAYED_RESPONSE.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context"
);

/* ------------------------------------------------------------------------- */
DOC(delayed_reply_error)
/* ------------------------------------------------------------------------- */
"delayed_reply_error(tctx, errstr) -> None\n\n"

"This function must be used to return an error when tha actual callback\n"
"returned CONFD_DELAYED_RESPONSE.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(delayed_reply_validation_warn)
/* ------------------------------------------------------------------------- */
"delayed_reply_validation_warn(tctx) -> None\n\n"

"This function must be used to return the equivalent of CONFD_VALIDATION_WARN\n"
"when the cb_validate() callback returned CONFD_DELAYED_RESPONSE.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context"
);

/* ------------------------------------------------------------------------- */
DOC(register_db_cb)
/* ------------------------------------------------------------------------- */
"register_db_cb(dx, dbcbs) -> None\n\n"

"This function is used to set callback functions which span over several\n"
"ConfD transactions.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* dbcbs -- the callback instance (see below)\n\n"

"The dbcbs argument should be an instance of a class with callback methods.\n"

"E.g.:\n\n"

"    class DbCallbacks(object):\n"
"        def cb_candidate_commit(self, dbx, timeout):\n"
"            pass\n\n"

"        def cb_candidate_confirming_commit(self, dbx):\n"
"            pass\n\n"

"        def cb_candidate_reset(self, dbx):\n"
"            pass\n\n"

"        def cb_candidate_chk_not_modified(self, dbx):\n"
"            pass\n\n"

"        def cb_candidate_rollback_running(self, dbx):\n"
"            pass\n\n"

"        def cb_candidate_validate(self, dbx):\n"
"            pass\n\n"

"        def cb_add_checkpoint_running(self, dbx):\n"
"            pass\n\n"

"        def cb_del_checkpoint_running(self, dbx):\n"
"            pass\n\n"

"        def cb_activate_checkpoint_running(self, dbx):\n"
"            pass\n\n"

"        def cb_copy_running_to_startup(self, dbx):\n"
"            pass\n\n"

"        def cb_running_chk_not_modified(self, dbx):\n"
"            pass\n\n"

"        def cb_lock(self, dbx, dbname):\n"
"            pass\n\n"

"        def cb_unlock(self, dbx, dbname):\n"
"            pass\n\n"

"        def cb_lock_partial(self, dbx, dbname, lockid, paths):\n"
"            pass\n\n"

"        def cb_ulock_partial(self, dbx, dbname, lockid):\n"
"            pass\n\n"

"        def cb_delete_confid(self, dbx, dbname):\n"
"            pass\n\n"

"    dbcbs = DbCallbacks()\n"
"    dp.register_db_cb(dx, dbcbs)"
);

/* ------------------------------------------------------------------------- */
DOC(db_set_timeout)
/* ------------------------------------------------------------------------- */
"db_set_timeout(dbx, timeout_secs) -> None\n\n"

"Some of the DB callbacks registered via register_db_cb(), e.g.\n"
"cb_copy_running_to_startup(), may require a longer execution time than\n"
"others. This function can be used to extend the timeout for the current\n"
"callback invocation. The timeout is given in seconds from the point in\n"
"time when the function is called.\n\n"

"Keyword arguments:\n\n"

"* dbx -- a db context of DbCtxRef\n"
"* timeout_secs -- timeout value"
);

/* ------------------------------------------------------------------------- */
DOC(db_seterr)
/* ------------------------------------------------------------------------- */
"db_seterr(dbx, errstr) -> None\n\n"

"This function is used by the application to set an error string.\n\n"

"Keyword arguments:\n\n"

"* dbx -- a db context\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(db_seterr_extended)
/* ------------------------------------------------------------------------- */
"db_seterr_extended(dbx, code, apptag_ns, apptag_tag, errstr) -> None\n\n"

"This function can be used to provide more structured error information\n"
"from a db callback.\n\n"

"Keyword arguments:\n\n"

"* dbx -- a db context\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(db_seterr_extended_info)
/* ------------------------------------------------------------------------- */
"db_seterr_extended_info(dbx, code, apptag_ns, apptag_tag,\n"
"                        error_info, errstr) -> None\n\n"

"This function can be used to provide structured error information in the\n"
"same way as db_seterr_extended(), and additionally provide contents for\n"
"the NETCONF <error-info> element.\n\n"

"Keyword arguments:\n\n"

"* dbx -- a db context\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* error_info -- a list of _lib.TagValue instances\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(aaa_reload)
/* ------------------------------------------------------------------------- */
"aaa_reload(tctx) -> None\n\n"

"When the ConfD AAA tree is populated by an external data provider (see the\n"
"AAA chapter in the User Guide), this function can be used by the data\n"
"provider to notify ConfD when there is a change to the AAA data.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context"
);

/* ------------------------------------------------------------------------- */
DOC(register_auth_cb)
/* ------------------------------------------------------------------------- */
"register_auth_cb(dx, acb) -> None\n\n"

"Registers the authentication callback.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* abc -- the callback instance (see below)\n\n"

"E.g.:\n\n"

"    class AuthCallbacks(object):\n"
"        def cb_auth(self, actx):\n"
"            pass\n\n"

"    acb = AuthCallbacks()\n"
"    dp.register_auth_cb(dx, acb)"
);

/* ------------------------------------------------------------------------- */
DOC(auth_seterr)
/* ------------------------------------------------------------------------- */
"auth_seterr(actx, errstr) -> None\n\n"

"This function is used by the application to set an error string.\n\n"
"This function can be used to provide a text message when the callback\n"
"returns CONFD_ERR. If used when rejecting a successful authentication, the\n"
"message will be logged in ConfD's audit log (otherwise a generic \"rejected\n"
"by application callback\" message is logged).\n\n"

"Keyword arguments:\n\n"

"* actx -- the auth context\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(register_authorization_cb)
/* ------------------------------------------------------------------------- */
"register_authorization_cb(dx, acb, cmd_filter, data_filter) -> None\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* abc -- the callback instance (see below)\n"
"* cmd_filter -- set to 0 for no filtering\n"
"* data_filter -- set to 0 for no filtering\n\n"

"E.g.:\n\n"

"    class AuthorizationCallbacks(object):\n"
"        def cb_chk_cmd_access(self, actx, cmdtokens, cmdop):\n"
"            pass\n\n"

"        def cb_chk_data_access(self, actx, hashed_ns, hkp, dataop, how):\n"
"            pass\n\n"

"    acb = AuthCallbacks()\n"
"    dp.register_authorization_cb(dx, acb)"
);

/* ------------------------------------------------------------------------- */
DOC(access_reply_result)
/* ------------------------------------------------------------------------- */
"access_reply_result(actx, result) -> None\n\n"

"The callbacks must call this function to report the result of the access\n"
"check to ConfD, and should normally return CONFD_OK. If any other value is\n"
"returned, it will cause the access check to be rejected.\n\n"

"Keyword arguments:\n\n"

"* actx -- the authorization context\n"
"* result -- the result (ACCESS_RESULT_xxx)"
);

/* ------------------------------------------------------------------------- */
DOC(authorization_set_timeout)
/* ------------------------------------------------------------------------- */
"authorization_set_timeout(actx, timeout_secs) -> None\n\n"

"The authorization callbacks are invoked on the daemon control socket, and\n"
"as such are expected to complete quickly. However in case they send requests\n"
"to a remote server, and such a request needs to be retried, this function\n"
"can be used to extend the timeout for the current callback invocation. The\n"
"timeout is given in seconds from the point in time when the function is\n"
"called.\n\n"

"Keyword arguments:\n\n"

"* actx -- the authorization context\n"
"* timeout_secs -- timeout value"
);

/* ------------------------------------------------------------------------- */
DOC(register_error_cb)
/* ------------------------------------------------------------------------- */
"register_error_cb(dx, errortypes, ecbs) -> None\n\n"

"This funciton can be used to register error callbacks that are\n"
"invoked for internally generated errors.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* errortypes -- logical OR of the error types that the ecbs should handle\n"
"* ecbs -- the callback instance (see below)\n\n"

"E.g.:\n\n"

"    class ErrorCallbacks(object):\n"
"        def cb_format_error(self, uinfo, errinfo_dict, default_msg):\n"
"            dp.error_seterr(uinfo, default_msg)\n"

"    ecbs = ErrorCallbacks()\n"
"    dp.register_error_cb(ctx,\n"
"                         dp.ERRTYPE_BAD_VALUE |\n"
"                         dp.ERRTYPE_MISC, ecbs)\n"
"    dp.register_done(ctx)"
);

/* ------------------------------------------------------------------------- */
DOC(error_seterr)
/* ------------------------------------------------------------------------- */
"error_seterr(uinfo, errstr) -> None\n\n"

"This function must be called by format_error() (above) to provide a\n"
" replacement for the default error message. If format_error() is called\n"
" without calling error_seterr() the default message will be used.\n\n"

"Keyword arguments:\n\n"

"* uinfo -- a user info context\n"
"* errstr -- an string describing the error"
);

/* ------------------------------------------------------------------------- */
DOC(register_usess_cb)
/* ------------------------------------------------------------------------- */
"register_usess_cb(dx, ucb) -> None\n\n"

"This function can be used to register information callbacks that are\n"
"invoked for user session start and stop.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* ucb -- the callback instance (see below)\n\n"

"E.g.:\n\n"

"    class UserSessionCallbacks(object):\n"
"        def cb_start(self, dx, uinfo):\n"
"            pass\n\n"

"        def cb_stop(self, dx, uinfo):\n"
"            pass\n\n"

"    ucb = UserSessionCallbacks()\n"
"    dp.register_usess_cb(dx, acb)"
);

/* ------------------------------------------------------------------------- */
DOC(install_crypto_keys)
/* ------------------------------------------------------------------------- */
"install_crypto_keys(dtx) -> None\n\n"

"It is possible to define DES3 and AES keys inside confd.conf. These keys\n"
"are used by ConfD to encrypt data which is entered into the system which\n"
"has either of the two builtin types tailf:des3-cbc-encrypted-string or\n"
"tailf:aes-cfb-128-encrypted-string.\n"
"This function will copy those keys from ConfD (which reads confd.conf) into\n"
"memory in the library.\n\n"

"This function must be called before register_done() is called.\n\n"

"Keyword arguments:\n\n"

"* dtx -- a daemon context wich is connected through a call to connect()"
);

/* ------------------------------------------------------------------------- */
DOC(register_notification_stream)
/* ------------------------------------------------------------------------- */
"register_notification_stream(dx, ncbs, sock, streamname) -> "
"NotificationCtxRef\n\n"

"This function registers the notification stream and optionally two callback\n"
"functions used for the replay functionality.\n\n"

"The returned notification context must be used by the application for the\n"
"sending of live notifications via notification_send() or\n"
"notification_send_path().\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* ncbs -- the callback instance (see below)\n"
"* sock -- a previously connected worker socket\n"
"* streamname -- the name of the notification stream\n\n"

"E.g.:\n\n"

"    class NotificationCallbacks(object):\n"
"        def cb_get_log_times(self, nctx):\n"
"            pass\n\n"

"        def cb_replay(self, nctx, start, stop):\n"
"            pass\n\n"

"    ncbs = NotificationCallbacks()\n"
"    livectx = dp.register_notification_stream(dx, ncbs, workersock,\n"
"    'streamname')"
);

/* ------------------------------------------------------------------------- */
DOC(notification_send)
/* ------------------------------------------------------------------------- */
"notification_send(nctx, time, values) -> None\n\n"

"This function is called by the application to send a notification defined\n"
"at the top level of a YANG module, whether \"live\" or replay.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* time -- a _lib.DateTime instance\n"
"* values -- a list of _lib.TagValue instances or None\n\n"
);

/* ------------------------------------------------------------------------- */
DOC(notification_send_path)
/* ------------------------------------------------------------------------- */
"notification_send_path(nctx, time, values, path) -> None\n\n"

"This function is called by the application to send a notification defined\n"
"as a child of a container or list in a YANG 1.1 module, whether \"live\" or\n"
"replay.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* time -- a _lib.DateTime instance\n"
"* values -- a list of _lib.TagValue instances or None\n"
"* path -- path to the parent of the notification in the data tree\n\n"
);

/* ------------------------------------------------------------------------- */
DOC(notification_reply_log_times)
/* ------------------------------------------------------------------------- */
"notification_reply_log_times(nctx, creation, aged) -> None\n\n"

"Reply function for use in the cb_get_log_times() callback invocation. If no\n"
"notifications have been aged out of the log, give None for the aged argument."
"\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* creation -- a _lib.DateTime instance\n"
"* aged -- a _lib.DateTime instance or None"
);

/* ------------------------------------------------------------------------- */
DOC(notification_replay_complete)
/* ------------------------------------------------------------------------- */
"notification_replay_complete(nctx) -> None\n\n"

"The application calls this function to notify ConfD that the replay is\n"
"complete\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
);

/* ------------------------------------------------------------------------- */
DOC(notification_replay_failed)
/* ------------------------------------------------------------------------- */
"notification_replay_failed(nctx) -> None\n\n"

"In case the application fails to complete the replay as requested (e.g. the\n"
"log gets overwritten while the replay is in progress), the application\n"
"should call this function instead of notification_replay_complete(). An\n"
"error message describing the reason for the failure can be supplied by\n"
"first calling notification_seterr() or notification_seterr_extended().\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
);

/* ------------------------------------------------------------------------- */
DOC(notification_set_fd)
/* ------------------------------------------------------------------------- */
"notification_set_fd(nctx, sock) -> None\n\n"

"This function may optionally be called by the cb_replay() callback to\n"
"request that the worker socket given by 'sock' should be used for the\n"
"replay. Otherwise the socket specified in register_notification_stream()\n"
"will be used.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* sock -- a previously connected worker socket"
);

/* ------------------------------------------------------------------------- */
DOC(notification_seterr)
/* ------------------------------------------------------------------------- */
"notification_seterr(nctx, errstr) -> None\n\n"

"In some cases the callbacks may be unable to carry out the requested\n"
"actions, e.g. the capacity for simultaneous replays might be exceeded, and\n"
"they can then return CONFD_ERR. This function allows the callback to\n"
"associate an error message with the failure. It can also be used to supply\n"
"an error message before calling notification_replay_failed().\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(notification_seterr_extended)
/* ------------------------------------------------------------------------- */
"notification_seterr_extended(nctx, code, apptag_ns, apptag_tag, errstr) ->"
"None\n\n"

"This function can be used to provide more structured error information\n"
"from a notification callback.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(notification_seterr_extended_info)
/* ------------------------------------------------------------------------- */
"notification_seterr_extended_info(nctx, code, apptag_ns, apptag_tag,\n"
"                                  error_info, errstr) -> None\n\n"

"This function can be used to provide structured error information in the\n"
"same way as notification_seterr_extended(), and additionally provide\n"
"contents for the NETCONF <error-info> element.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
"* code -- an error code\n"
"* apptag_ns -- namespace - should be set to 0\n"
"* apptag_tag -- either 0 or the hash value for a data model node\n"
"* error_info -- a list of _lib.TagValue instances\n"
"* errstr -- an error message string"
);

/* ------------------------------------------------------------------------- */
DOC(register_snmp_notification)
/* ------------------------------------------------------------------------- */
"register_snmp_notification(dx, sock, notify_name, ctx_name) -> "
"NotificationCtxRef\n\n"

"SNMP notifications can also be sent via the notification framework, however\n"
"most aspects of the stream concept do not apply for SNMP. This function is\n"
"used to register a worker socket, the snmpNotifyName (notify_name), and\n"
"SNMP context (ctx_name) to be used for the notifications.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* sock -- a previously connected worker socket\n"
"* notify_name -- the snmpNotifyName\n"
"* ctx_name -- the SNMP context"
);

/* ------------------------------------------------------------------------- */
DOC(notification_send_snmp)
/* ------------------------------------------------------------------------- */
"notification_send_snmp(nctx, notification, varbinds) -> None\n\n"

"Sends the SNMP notification specified by 'notification', without requesting\n"
"inform-request delivery information. This is equivalent to calling\n"
"notification_send_snmp_inform() with None as the cb_id argument. I.e. if\n"
"the common arguments are the same, the two functions will send the exact\n"
"same set of traps and inform-requests.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_snmp_notification()\n"
"* notification -- the notification string\n"
"* varbinds -- a list of _lib.SnmpVarbind instances or None"
);

/* ------------------------------------------------------------------------- */
DOC(notification_send_snmp_inform)
/* ------------------------------------------------------------------------- */
"notification_send_snmp_inform(nctx, notification, varbinds, cb_id, ref) ->"
"None\n\n"

"Sends the SNMP notification specified by notification. If cb_id is not None\n"
"the callbacks registered for cb_id will be invoked with the ref argument.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_snmp_notification()\n"
"* notification -- the notification string\n"
"* varbinds -- a list of _lib.SnmpVarbind instances or None\n"
"* cb_id -- callback id\n"
"* ref -- argument send to callbacks"
);

/* ------------------------------------------------------------------------- */
DOC(notification_set_snmp_src_addr)
/* ------------------------------------------------------------------------- */
"notification_set_snmp_src_addr(nctx, family, src_addr) -> None\n\n"

"By default, the source address for the SNMP notifications that are sent by\n"
"the above functions is chosen by the IP stack of the OS. This function may\n"
"be used to select a specific source address, given by src_addr, for the\n"
"SNMP notifications subsequently sent using the nctx context. The default\n"
"can be restored by calling the function with family set to AF_UNSPEC.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_snmp_notification()\n"
"* family -- AF_INET, AF_INET6 or AF_UNSPEC\n"
"* src_addr -- the source address in string format"
);

/* ------------------------------------------------------------------------- */
DOC(notification_set_snmp_notify_name)
/* ------------------------------------------------------------------------- */
"notification_set_snmp_notify_name(nctx, notify_name) -> None\n\n"

"This function can be used to change the snmpNotifyName (notify_name) for\n"
"the nctx context.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_snmp_notification()\n"
"* notify_name -- the snmpNotifyName"
);

/* ------------------------------------------------------------------------- */
DOC(notification_flush)
/* ------------------------------------------------------------------------- */
"notification_flush(nctx) -> None\n\n"

"Notifications are sent asynchronously, i.e. normally without blocking the\n"
"caller of the send functions described above. This means that in some cases\n"
"ConfD's sending of the notifications on the northbound interfaces may lag\n"
"behind the send calls. This function can be used  to make sure that the\n"
"notifications have actually been sent out.\n\n"

"Keyword arguments:\n\n"

"* nctx -- notification context returned from register_notification_stream()\n"
);

/* ------------------------------------------------------------------------- */
DOC(register_notification_snmp_inform_cb)
/* ------------------------------------------------------------------------- */
"register_notification_snmp_inform_cb(dx, cb_id, cbs) -> None\n\n"

"If we want to receive information about the delivery of SNMP\n"
"inform-requests, we must register two callbacks for this.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* cb_id -- the callback identifier\n"
"* cbs -- the callback instance (see below)\n\n"

"E.g.:\n\n"

"    class NotifySnmpCallbacks(object):\n"
"        def cb_targets(self, nctx, ref, targets):\n"
"            pass\n\n"

"        def cb_result(self, nctx, ref, target, got_response):\n"
"            pass\n\n"

"    cbs = NotifySnmpCallbacks()\n"
"    dp.register_notification_snmp_inform_cb(dx, 'callback-id-1', cbs)"
);

/* ------------------------------------------------------------------------- */
DOC(register_notification_sub_snmp_cb)
/* ------------------------------------------------------------------------- */
"register_notification_sub_snmp_cb(dx, sub_id, cbs) -> None\n\n"

"Registers a callback function to be called when an SNMP notification is\n"
"received by the SNMP gateway.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* sub_id -- the subscription id for the notifications\n"
"* cbs -- the callback instance (see below)\n\n"

"E.g.:\n\n"

"    class NotifySubSnmpCallbacks(object):\n"
"        def cb_recv(self, nctx, notification, varbinds, src_addr, port):\n"
"            pass\n\n"

"    cbs = NotifySubSnmpCallbacks()\n"
"    dp.register_notification_sub_snmp_cb(dx, 'sub-id-1', cbs)"
);


#ifdef CONFD_PY_PRODUCT_NCS

/* ------------------------------------------------------------------------- */
DOC(register_service_cb)
/* ------------------------------------------------------------------------- */
"register_service_cb(dx, servicepoint, scb) -> None\n\n"

"This function registers the service callbacks.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* servicepoint -- name of the service point (string)\n"
"* scb -- the callback instance (see below)\n\n"

"E.g:\n\n"

"    class ServiceCallbacks(object):\n"
"        def cb_create(self, tctx, kp, proplist, fastmap_thandle):\n"
"            pass\n\n"

"        def cb_pre_modification(self, tctx, op, kp, proplist):\n"
"            pass\n\n"

"        def cb_post_modification(self, tctx, op, kp, proplist):\n"
"            pass\n\n"

"    scb = ServiceCallbacks()\n"
"    dp.register_service_cb(dx, 'service-point-1', scb)"
);

/* ------------------------------------------------------------------------- */
DOC(service_reply_proplist)
"service_reply_proplist(tctx, proplist) -> None\n\n"

"This function must be called with the new property list, immediately prior\n"
"to returning from the callback, if the stored property list should be\n"
"updated. If a callback returns without calling service_reply_proplist(),\n"
"the previous property list is retained. To completely delete the property\n"
"list, call this function with the proplist argument set to an empty list or\n"
"None.\n\n"

"The proplist argument should be a list of 2-tuples built up like this:\n"
"  list( (name, value), (name, value), ... )\n"
"In a 2-tuple both 'name' and 'value' must be strings.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* proplist -- a list of properties or None"
);


/* ------------------------------------------------------------------------- */
DOC(register_nano_service_cb)
/* ------------------------------------------------------------------------- */
"register_nano_service_cb(dx,servicepoint,componenttype,state,nscb) -> None\n\n"

"This function registers the nano service callbacks.\n\n"

"Keyword arguments:\n\n"

"* dx -- a daemon context acquired through a call to init_daemon()\n"
"* servicepoint -- name of the service point (string)\n"
"* componenttype -- name of the plan component for the nano service (string)\n"
"* state -- name of component state for the nano service (string)\n"
"* nscb -- the nano callback instance (see below)\n\n"

"E.g:\n\n"

"    class NanoServiceCallbacks(object):\n"
"        def cb_nano_create(self, tctx, root, service, plan,\n"
"                           component, state, proplist, compproplist):\n"
"            pass\n\n"
"        def cb_nano_delete(self, tctx, root, service, plan,\n"
"                           component, state, proplist, compproplist):\n"
"            pass\n\n"
"    nscb = NanoServiceCallbacks()\n"
"    dp.register_nano_service_cb(dx, 'service-point-1', 'comp', 'state', nscb)"
);

/* ------------------------------------------------------------------------- */
DOC(nano_service_reply_proplist)
"nano_service_reply_proplist(tctx, proplist) -> None\n\n"

"This function must be called with the new property list, immediately prior\n"
"to returning from the callback, if the stored property list should be\n"
"updated. If a callback returns without calling "
"nano_service_reply_proplist(),\n"
"the previous property list is retained. To completely delete the property\n"
"list, call this function with the proplist argument set to an empty list or\n"
"None.\n\n"

"The proplist argument should be a list of 2-tuples built up like this:\n"
"  list( (name, value), (name, value), ... )\n"
"In a 2-tuple both 'name' and 'value' must be strings.\n\n"

"Keyword arguments:\n\n"

"* tctx -- a transaction context\n"
"* proplist -- a list of properties or None"
);

#endif /* CONFD_PY_PRODUCT_NCS */

#undef DOC
