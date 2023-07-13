/*
 * dp documentation to be included in _cdb.c
 */

#define CDB_MODULE_DOCSTR(PROD) \
"Low level module for connecting to " PROD " built-in XML database (CDB).\n"\
"\n"\
"This module is used to connect to the " PROD " built-in XML database, CDB.\n"\
"The purpose of this API is to provide a read and subscription API to CDB.\n"\
"\n"\
"CDB owns and stores the configuration data and the user of the API wants\n"\
"to read that configuration data and also get notified when someone through\n"\
"either NETCONF, SNMP, the CLI, the Web UI or the MAAPI modifies the data\n"\
"so that the application can re-read the configuration data and act\n"\
"accordingly.\n"\
"\n"\
"CDB can also store operational data, i.e. data which is designated with a\n"\
"\"config false\" statement in the YANG data model. Operational data can be\n"\
"both read and written by the applications, but NETCONF and the other\n"\
"northbound agents can only read the operational data.\n"\
"\n"\
"This documentation should be read together with the confd_lib_cdb(3) man page."

#define DOC(name) PyDoc_STRVAR(_cdb_ ## name ## __doc__,

/* ------------------------------------------------------------------------- */
DOC(connect)
/* ------------------------------------------------------------------------- */
"connect(sock, type, ip, port, path) -> None\n\n"

"The application has to connect to NCS before it can interact. There are two\n"
"different types of connections identified by the type argument -\n"
"DATA_SOCKET and SUBSCRIPTION_SOCKET.\n\n"

"Keyword arguments:\n\n"

"* sock -- a Python socket instance\n"
"* type -- DATA_SOCKET or SUBSCRIPTION_SOCKET\n"
"* ip -- the ip address if socket is AF_INET (optional)\n"
"* port -- the port if socket is AF_INET (optional)\n"
"* path -- a filename if socket is AF_UNIX (optional)."
);

/* ------------------------------------------------------------------------- */
DOC(connect_name)
/* ------------------------------------------------------------------------- */
"connect_name(sock, type, name, ip, port, path) -> None\n\n"

"When we use connect() to create a connection to NCS/CDB, the name\n"
"argument passed to the library initialization function confd_init() (see\n"
"confd_lib_lib(3)) is used to identify the connection in status reports and\n"
"logs. I we want different names to be used for different connections from\n"
"the same application process, we can use connect_name() with the wanted\n"
"name instead of connect().\n\n"

"Keyword arguments:\n\n"

"* sock -- a Python socket instance\n"
"* type -- DATA_SOCKET or SUBSCRIPTION_SOCKET\n"
"* name -- the name\n"
"* ip -- the ip address if socket is AF_INET (optional)\n"
"* port -- the port if socket is AF_INET (optional)\n"
"* path -- a filename if socket is AF_UNIX (optional)."
);

/* ------------------------------------------------------------------------- */
DOC(mandatory_subscriber)
/* ------------------------------------------------------------------------- */
"mandatory_subscriber(sock, name) -> None\n\n"

"Attaches a mandatory attribute and a mandatory name to the subscriber\n"
"identified by sock. The name argument is distinct from the name argument\n"
"in connect_name().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* name -- the name"
);

/* ------------------------------------------------------------------------- */
DOC(set_namespace)
/* ------------------------------------------------------------------------- */
"set_namespace(sock, hashed_ns) -> None\n\n"

"If we want to access data in CDB where the toplevel element name is not\n"
"unique, we need to set the namespace. We are reading data related to a\n"
"specific .fxs file. confdc can be used to generate a .py file with a class\n"
"for the namespace, by the flag --emit-python to confdc (see confdc(1)).\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* hashed_ns -- the namespace hash"
);

/* ------------------------------------------------------------------------- */
DOC(start_session)
/* ------------------------------------------------------------------------- */
"start_session(sock, db) -> None\n\n"

"Starts a new session on an already established socket to CDB. The db\n"
"parameter should be one of RUNNING, PRE_COMMIT_RUNNING, STARTUP and\n"
"OPERATIONAL.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* db -- the database"
);

/* ------------------------------------------------------------------------- */
DOC(start_session2)
/* ------------------------------------------------------------------------- */
"start_session2(sock, db, flags) -> None\n\n"

"This function may be used instead of start_session() if it is considered\n"
"necessary to have more detailed control over some aspects of the CDB\n"
"session - if in doubt, use start_session() instead. The sock and db\n"
"arguments are the same as for start_session(), and these values can be used\n"
"for flags (ORed together if more than one).\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* db -- the database\n"
"* flags -- the flags"
);

/* ------------------------------------------------------------------------- */
DOC(end_session)
/* ------------------------------------------------------------------------- */
"end_session(sock) -> None\n\n"

"We use connect() to establish a read socket to CDB. When the socket is\n"
"closed, the read session is ended. We can reuse the same socket for another\n"
"read session, but we must then end the session and create another session\n"
"using start_session().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(close)
/* ------------------------------------------------------------------------- */
"close(sock) -> None\n\n"

"Closes the socket. end_session() should be called before calling this\n"
"function.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(wait_start)
/* ------------------------------------------------------------------------- */
"wait_start(sock) -> None\n\n"

"This call waits until CDB has completed start-phase 1 and is available,\n"
"when it is CONFD_OK is returned. If CDB already is available (i.e.\n"
"start-phase >= 1) the call returns immediately. This can be used by a CDB\n"
"client who is not synchronously started and only wants to wait until it\n"
"can read its configuration. The call can be used after connect().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(get_txid)
/* ------------------------------------------------------------------------- */
"get_txid(sock) -> tuple\n\n"

"Read the last transaction id from CDB. This function can be used if we are\n"
"forced to reconnect to CDB. If the transaction id we read is identical to\n"
"the last id we had prior to loosing the CDB sockets we don't have to reload\n"
"our managed object data. See the User Guide for full explanation.\n\n"

"The returned tuple has the form (s1, s2, s3, primary) where s1, s2 and s3\n"
"are unsigned integers and primary is either a string or None.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(get_replay_txids)
/* ------------------------------------------------------------------------- */
"get_replay_txids(sock) -> List[Tuple]\n\n"

"When the subscriptionReplay functionality is enabled in confd.conf this\n"
"function returns the list of available transactions that CDB can replay.\n"
"The current transaction id will be the first in the list, the second at\n"
"txid[1] and so on. In case there are no replay transactions available (the\n"
"feature isn't enabled or there hasn't been any transactions yet) only one\n"
"(the current) transaction id is returned.\n\n"

"The returned list contains tuples with the form (s1, s2, s3, primary) where\n"
"s1, s2 and s3 are unsigned integers and primary is either a string or None.\n"

"\nKeyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(initiate_journal_compaction)
/* ------------------------------------------------------------------------- */
"initiate_journal_compaction(sock) -> None\n\n"

"Normally CDB handles journal compaction of the config datastore\n"
"automatically. If this has been turned off (in the configuration file)\n"
"then the A.cdb file will grow indefinitely unless this API function is\n"
"called periodically to initiate compaction. This function initiates a\n"
"compaction and returns immediately (if the datastore is locked, the\n"
"compaction will be delayed, but eventually compaction will take place).\n"
"Calling this function when journal compaction is configured to be automatic\n"
"has no effect.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(get_user_session)
/* ------------------------------------------------------------------------- */
"get_user_session(sock) -> int\n\n"

"Returns the user session id for the transaction that triggered the\n"
"current subscription notification. This function uses a subscription\n"
"socket, and can only be called when a subscription notification for\n"
"configuration data has been received on that socket, before\n"
"sync_subscription_socket() has been called. Additionally, it is not\n"
"possible to call this function from the iter() function passed to\n"
"diff_iterate(). To retrieve full information about the user session,\n"
"use _maapi.get_user_session() (see confd_lib_maapi(3)).\n\n"

"Note:\n"
">    When the ConfD High Availability functionality is used, the\n"
">    user session information is not available on secondary nodes.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(get_transaction_handle)
/* ------------------------------------------------------------------------- */
"get_transaction_handle(sock) -> int\n\n"

"Returns the transaction handle for the transaction that triggered the\n"
"current subscription notification. This function uses a subscription\n"
"socket, and can only be called when a subscription notification for\n"
"configuration data has been received on that socket, before\n"
"sync_subscription_socket() has been called. Additionally, it is not\n"
"possible to call this function from the iter() function passed to\n"
"diff_iterate().\n\n"

"Note:\n"
">    A CDB client is not expected to access the ConfD transaction store\n"
">    directly - this function should only be used for logging or debugging\n"
">    purposes.\n\n"

"Note:\n"
">    When the ConfD High Availability functionality is used, the\n"
">    transaction information is not available on secondary nodes.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(set_timeout)
/* ------------------------------------------------------------------------- */
"set_timeout(sock, timeout_secs) -> None\n\n"

"A timeout for client actions can be specified via\n"
"/confdConfig/cdb/clientTimeout in confd.conf, see the confd.conf(5)\n"
"manual page. This function can be used to dynamically extend (or shorten)\n"
"the timeout for the current action. Thus it is possible to configure a\n"
"restrictive timeout in confd.conf, but still allow specific actions to\n"
"have a longer execution time.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* timeout_secs -- timeout in seconds"
);

/* ------------------------------------------------------------------------- */
DOC(get_phase)
/* ------------------------------------------------------------------------- */
"get_phase(sock) -> dict\n\n"

"Returns the start-phase that CDB is currently in. The return value is a\n"
"dict of the form:\n\n"

"    {\n"
"       'phase': phase,\n"
"       'flags': flags,\n"
"       'init': init,\n"
"       'upgrade': upgrade\n"
"    }\n\n"

"In this dict 'phase' and 'flags' are integers, while 'init' and 'upgrade'\n"
"are booleans.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(exists)
/* ------------------------------------------------------------------------- */
"exists(sock, path) -> bool\n\n"

"Leafs in the data model may be optional, and presence containers and list\n"
"entries may or may not exist. This function checks whether a node exists\n"
"in CDB.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to check for existence"
);

/* ------------------------------------------------------------------------- */
DOC(num_instances)
/* ------------------------------------------------------------------------- */
"num_instances(sock, path) -> int\n\n"

"Returns the number of instances in a list.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to list node"
);

/* ------------------------------------------------------------------------- */
DOC(next_index)
/* ------------------------------------------------------------------------- */
"next_index(sock, path) -> int\n\n"

"Given a path to a list entry next_index() returns the position\n"
"(starting from 0) of the next entry (regardless of whether the path\n"
"exists or not).\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to list entry"
);

/* ------------------------------------------------------------------------- */
DOC(index)
/* ------------------------------------------------------------------------- */
"index(sock, path) -> int\n\n"

"Given a path to a list entry index() returns its position (starting from 0)."
"\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to list entry"
);

/* ------------------------------------------------------------------------- */
DOC(is_default)
/* ------------------------------------------------------------------------- */
"is_default(sock, path) -> bool\n\n"

"This function returns True for a leaf which has a default value defined in\n"
"the data model when no value has been set, i.e. when the default value is\n"
"in effect. It returns False for other existing leafs.\n"
"There is normally no need to call this function, since CDB automatically\n"
"provides the default value as needed when get() etc is called.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to leaf"
);

/* ------------------------------------------------------------------------- */
DOC(cd)
/* ------------------------------------------------------------------------- */
"cd(sock, path) -> None\n\n"

"Changes the working directory according to the format path. Note that\n"
"this function can not be used as an existence test.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to cd to"
);

/* ------------------------------------------------------------------------- */
DOC(pushd)
/* ------------------------------------------------------------------------- */
"pushd(sock, path) -> None\n\n"

"Similar to cd() but pushes the previous current directory on a stack.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to cd to"
);

/* ------------------------------------------------------------------------- */
DOC(popd)
/* ------------------------------------------------------------------------- */
"popd(sock) -> None\n\n"

"Pops the top element from the directory stack and changes directory to\n"
"previous directory.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(getcwd)
/* ------------------------------------------------------------------------- */
"getcwd(sock) -> str\n\n"

"Returns the current position as previously set by cd(), pushd(), or popd()\n"
"as a string path. Note that what is returned is a pretty-printed version of\n"
"the internal representation of the current position. It will be the shortest\n"
"unique way to print the path but it might not exactly match the string given\n"
"to cd().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(getcwd_kpath)
/* ------------------------------------------------------------------------- */
"getcwd_kpath(sock) -> " CONFD_PY_MODULE ".HKeypathRef\n\n"

"Returns the current position like getcwd(), but as a HKeypathRef\n"
"instead of as a string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(get)
/* ------------------------------------------------------------------------- */
"get(sock, path) -> " CONFD_PY_MODULE ".Value\n\n"

"This reads a a value from the path and returns the result. The path must\n"
"lead to a leaf element in the XML data tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- path to leaf"
);

/* ------------------------------------------------------------------------- */
DOC(subscribe)
/* ------------------------------------------------------------------------- */
"subscribe(sock, prio, nspace, path) -> int\n\n"

"Sets up a CDB subscription so that we are notified when CDB configuration\n"
"data changes. There can be multiple subscription points from different\n"
"sources, that is a single client daemon can have many subscriptions and\n"
"there can be many client daemons. The return value is a subscription point\n"
"used to identify this particular subscription.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* prio -- priority\n"
"* nspace -- the namespace hash\n"
"* path -- path to node"
);

/* ------------------------------------------------------------------------- */
DOC(subscribe2)
/* ------------------------------------------------------------------------- */
"subscribe2(sock, type, flags, prio, nspace, path) -> int\n\n"

"This function supersedes the current subscribe() and oper_subscribe() as\n"
"well as makes it possible to use the new two phase subscription method.\n"

"Operational and configuration subscriptions can be done on the same\n"
"socket, but in that case the notifications may be arbitrarily interleaved,\n"
"including operational notifications arriving between different configuration\n"
"notifications for the same transaction. If this is a problem, use separate\n"
"sockets for operational and configuration subscriptions.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* type -- subscription type\n"
"* flags -- flags\n"
"* prio -- priority\n"
"* nspace -- the namespace hash\n"
"* path -- path to node"
);

/* ------------------------------------------------------------------------- */
DOC(oper_subscribe)
/* ------------------------------------------------------------------------- */
"oper_subscribe(sock, nspace, path) -> int\n\n"

"Sets up a CDB subscription for changes in the operational database.\n"
"Similar to the subscriptions for configuration data, we can be notified\n"
"of changes to the operational data stored in CDB. Note that there are\n"
"several differences from the subscriptions for configuration data.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* nspace -- the namespace hash\n"
"* path -- path to node"
);

/* ------------------------------------------------------------------------- */
DOC(subscribe_done)
/* ------------------------------------------------------------------------- */
"subscribe_done(sock) -> None\n\n"

"When a client is done registering all its subscriptions on a particular\n"
"subscription socket it must call subscribe_done(). No notifications will be\n"
"delivered until then.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(trigger_subscriptions)
/* ------------------------------------------------------------------------- */
"trigger_subscriptions(sock, sub_points) -> None\n\n"

"This function makes it possible to trigger CDB subscriptions for\n"
"configuration data even though the configuration has not been modified.\n"
"The caller will trigger all subscription points passed in the sub_points\n"
"list (or all subscribers if the list is empty) in priority order, and the\n"
"call will not return until the last subscriber has called\n"
"sync_subscription_socket().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* sub_points -- a list of subscription points"
);

/* ------------------------------------------------------------------------- */
DOC(trigger_oper_subscriptions)
/* ------------------------------------------------------------------------- */
"trigger_oper_subscriptions(sock, sub_points, flags) -> None\n\n"

"This function works like trigger_subscriptions(), but for CDB\n"
"subscriptions to operational data. The caller will trigger all\n"
"subscription points passed in the sub_points list (or all operational\n"
"data subscribers if the list is empty), and the call will not return until\n"
"the last subscriber has called sync_subscription_socket().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* sub_points -- a list of subscription points\n"
"* flags -- the flags"
);

/* ------------------------------------------------------------------------- */
DOC(diff_iterate)
/* ------------------------------------------------------------------------- */
"diff_iterate(sock, subid, iter, flags, initstate) -> int\n\n"

"After reading the subscription socket the diff_iterate() function can be\n"
"used to iterate over the changes made in CDB data that matched the\n"
"particular subscription point given by subid.\n\n"

"The user defined function iter() will be called for each element that has\n"
"been modified and matches the subscription.\n\n"

"This function will return the last return value from the iter() callback.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* subid -- the subcscription id\n"
"* iter -- iterator function (see below)\n"
"* initstate -- opaque passed to iter function\n\n"

"The user defined function iter() will be called for each element that has\n"
"been modified and matches the subscription. It must have the following\n"
"signature:\n\n"

"    iter_fn(kp, op, oldv, newv, state) -> int\n\n"

"Where arguments are:\n\n"

"* kp - a HKeypathRef or None\n"
"* op - the operation\n"
"* oldv - the old value or None\n"
"* newv - the new value or None\n"
"* state - the initstate object"
);

/* ------------------------------------------------------------------------- */
DOC(diff_iterate_resume)
/* ------------------------------------------------------------------------- */
"diff_iterate_resume(sock, reply, iter, resumestate) -> int\n\n"

"The application must call this function whenever an iterator function has\n"
"returned ITER_SUSPEND to finish up the iteration. If the application does\n"
"not wish to continue iteration it must at least call\n"
"diff_iterate_resume(sock, ITER_STOP, None, None) to clean up the state.\n"
"The reply parameter is what the iterator function would have returned\n"
"(i.e. normally ITER_RECURSE or ITER_CONTINUE) if it hadn't returned\n"
"ITER_SUSPEND.\n\n"

"This function will return the last return value from the iter() callback.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* reply -- the reply value\n"
"* iter -- iterator function (see diff_iterate())\n"
"* resumestate -- opaque passed to iter function\n\n"
);

/* ------------------------------------------------------------------------- */
DOC(replay_subscriptions)
/* ------------------------------------------------------------------------- */
"replay_subscriptions(sock, txid, sub_points) -> None\n\n"

"This function makes it possible to replay the subscription events for the\n"
"last configuration change to some or all CDB subscribers. This call is\n"
"useful in a number of recovery scenarios, where some CDB subscribers lost\n"
"connection to ConfD before having received all the changes in a\n"
"transaction. The replay functionality is only available if it has been\n"
"enabled in confd.conf.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* txid -- a 4-tuple of the form (s1, s2, s3, primary)\n"
"* sub_points -- a list of subscription points"
);

/* ------------------------------------------------------------------------- */
DOC(read_subscription_socket)
/* ------------------------------------------------------------------------- */
"read_subscription_socket(sock) -> list\n\n"

"This call will return a list of integer values containing subscription\n"
"points earlier acquired through calls to subscribe().\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(read_subscription_socket2)
/* ------------------------------------------------------------------------- */
"read_subscription_socket2(sock) -> tuple\n\n"

"Another version of read_subscription_socket() which will return a 3-tuple\n"
"in the form (type, flags, subpoints).\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket"
);

/* ------------------------------------------------------------------------- */
DOC(get_modifications)
/* ------------------------------------------------------------------------- */
"get_modifications(sock, subid, flags, path) -> list\n\n"

"The get_modifications() function can be called after reception of a\n"
"subscription notification to retrieve all the changes that caused the\n"
"subscription notification. The socket sock is the subscription socket. The\n"
"subscription id must also be provided. Optionally a path can be used to\n"
"limit what is returned further (only changes below the supplied path will\n"
"be returned), if this isn't needed path can be set to None.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* subid -- subscription id\n"
"* flags -- the flags\n"
"* path -- a path in string format or None"
);

/* ------------------------------------------------------------------------- */
DOC(get_modifications_cli)
/* ------------------------------------------------------------------------- */
"get_modifications_cli(sock, subid, flags) -> str\n\n"

"The get_modifications_cli() function can be called after reception of\n"
"a subscription notification to retrieve all the changes that caused the\n"
"subscription notification as a string in Cisco CLI format. The socket sock\n"
"is the subscription socket. The subscription id must also be provided.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* subid -- subscription id\n"
"* flags -- the flags"
);

/* ------------------------------------------------------------------------- */
DOC(get_modifications_iter)
/* ------------------------------------------------------------------------- */
"get_modifications_iter(sock, flags) -> list\n\n"

"The get_modifications_iter() is basically a convenient short-hand of\n"
"the get_modifications() function intended to be used from within a\n"
"iteration function started by diff_iterate(). In this case no subscription\n"
"id is needed, and the path is implicitly the current position in the\n"
"iteration.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* flags -- the flags"
);

/* ------------------------------------------------------------------------- */
DOC(sub_progress)
/* ------------------------------------------------------------------------- */
"sub_progress(sock, msg) -> None\n\n"

"After receiving a subscription notification (using\n"
"read_subscription_socket()) but before acknowledging it (or aborting,\n"
"in the case of prepare subscriptions), it is possible to send progress\n"
"reports back to ConfD using the sub_progress() function.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* msg -- the message"
);

/* ------------------------------------------------------------------------- */
DOC(sub_abort_trans)
/* ------------------------------------------------------------------------- */
"sub_abort_trans(sock, code, apptag_ns, apptag_tag, reason) -> None\n\n"

"This function is to be called instead of sync_subscription_socket()\n"
"when the subscriber wishes to abort the current transaction. It is only\n"
"valid to call after read_subscription_socket2() has returned with\n"
"type set to CDB_SUB_PREPARE. The arguments after sock are the same as to\n"
"X_seterr_extended() and give the caller a way of indicating the\n"
"reason for the failure.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* code -- the error code\n"
"* apptag_ns -- the namespace hash\n"
"* apptag_tag -- the tag hash\n"
"* reason -- reason string"
);

/* ------------------------------------------------------------------------- */
DOC(sub_abort_trans_info)
/* ------------------------------------------------------------------------- */
"sub_abort_trans_info(sock, code, apptag_ns, apptag_tag, error_info, reason) "
"-> None\n\n"

"Same a sub_abort_trans() but also fills in the NETCONF <error-info> element."
"\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* code -- the error code\n"
"* apptag_ns -- the namespace hash\n"
"* apptag_tag -- the tag hash\n"
"* error_info -- a list of TagValue instances\n"
"* reason -- reason string"
);

/* ------------------------------------------------------------------------- */
DOC(set_elem)
/* ------------------------------------------------------------------------- */
"set_elem(sock, value, path) -> None\n\n"

"Set the value of a single leaf. The value may be either a Value instance or\n"
"a string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* value -- the value to set\n"
"* path -- a string pointing to a single leaf"
);

/* ------------------------------------------------------------------------- */
DOC(create)
/* ------------------------------------------------------------------------- */
"create(sock, path) -> None\n\n"

"Create a new list entry, presence container, or leaf of type empty. Note\n"
"that for list entries and containers, sub-elements will not exist until\n"
"created or set via some of the other functions, thus doing implicit\n"
"create via set_object() or set_values() may be preferred in this case.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- item to create (string)"
);

/* ------------------------------------------------------------------------- */
DOC(delete)
/* ------------------------------------------------------------------------- */
"delete(sock, path) -> None\n\n"

"Delete a list entry, presence container, or leaf of type empty, and all\n"
"its child elements (if any).\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- item to delete (string)"
);

/* ------------------------------------------------------------------------- */
DOC(set_object)
/* ------------------------------------------------------------------------- */
"set_object(sock, values, path) -> None\n\n"

"Set all elements corresponding to the complete contents of a container or\n"
"list entry, except for sub-lists.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* values -- a list of Value:s\n"
"* path -- path to container or list entry (string)"
);

/* ------------------------------------------------------------------------- */
DOC(set_values)
/* ------------------------------------------------------------------------- */
"set_values(sock, values, path) -> None\n\n"

"Set arbitrary sub-elements of a container or list entry.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* values -- a list of TagValue:s\n"
"* path -- path to container or list entry (string)"
);

/* ------------------------------------------------------------------------- */
DOC(get_case)
/* ------------------------------------------------------------------------- */
"get_case(sock, choice, path) -> None\n\n"

"When we use the YANG choice statement in the data model, this function\n"
"can be used to find the currently selected case, avoiding useless\n"
"get() etc requests for elements that belong to other cases.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* choice -- the choice (string)\n"
"* path -- path to container or list entry where choice is defined (string)"
);

/* ------------------------------------------------------------------------- */
DOC(set_case)
/* ------------------------------------------------------------------------- */
"set_case(sock, choice, scase, path) -> None\n\n"

"When we use the YANG choice statement in the data model, this function\n"
"can be used to select the current case.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* choice -- the choice (string)\n"
"* scase -- the case (string)\n"
"* path -- path to container or list entry where choice is defined (string)"
);

/* ------------------------------------------------------------------------- */
DOC(sync_subscription_socket)
/* ------------------------------------------------------------------------- */
"sync_subscription_socket(sock, st) -> None\n\n"

"Once we have read the subscription notification through a call to\n"
"read_subscription_socket() and optionally used the diff_iterate()\n"
"to iterate through the changes as well as acted on the changes to CDB, we\n"
"must synchronize with CDB so that CDB can continue and deliver further\n"
"subscription messages to subscribers with higher priority numbers.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* st -- sync type (int)"
);

/* ------------------------------------------------------------------------- */
DOC(get_values)
/* ------------------------------------------------------------------------- */
"get_values(sock, values, path) -> list\n\n"

"Read an arbitrary set of sub-elements of a container or list entry. The\n"
"values list must be pre-populated with a number of TagValue instances.\n\n"

"TagValues passed in the values list will be updated with the corresponding\n"
"values read and a new values list will be returned.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* values -- a list of TagValue instances\n"
"* path -- path to a list entry or a container (string)"
);

/* ------------------------------------------------------------------------- */
DOC(get_object)
/* ------------------------------------------------------------------------- */
"get_object(sock, n, path) -> list\n\n"

"This function reads at most n values from the container or list entry\n"
"specified by the path, and returns them as a list of Value's.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* n -- max number of values to read\n"
"* path -- path to a list entry or a container (string)"
);

/* ------------------------------------------------------------------------- */
DOC(get_objects)
/* ------------------------------------------------------------------------- */
"get_objects(sock, n, ix, nobj, path) -> list\n\n"

"Similar to get_object(), but reads multiple entries of a list based\n"
"on the \"instance integer\" otherwise given within square brackets in the\n"
"path - here the path must specify the list without the instance integer.\n"
"At most n values from each of nobj entries, starting at entry ix, are\n"
"read and placed in the values array. The return value is a list of objects\n"
"where each object is represented as a list of Values.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* n -- max number of values to read from each object\n"
"* ix -- start index\n"
"* nobj -- number of objects to read\n"
"* path -- path to a list entry or a container (string)"
);

/* ------------------------------------------------------------------------- */
DOC(cs_node_cd)
/* ------------------------------------------------------------------------- */
"cs_node_cd(socket, path) -> Union["
    CONFD_PY_MODULE ".CsNode, None]\n\n"

"Utility function which finds the resulting CsNode given a string keypath.\n\n"

"Does the same thing as " _TM ".cs_node_cd(), but can handle paths that are \n"
"ambiguous due to traversing a mount point, by sending a request to the \n"
"daemon\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected CDB socket\n"
"* path -- the path"
);



#undef DOC
