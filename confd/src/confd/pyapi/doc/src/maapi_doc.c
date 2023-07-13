/*
 * maapi documentation to be included in _maapi.c
 */

#define MAAPI_MODULE_DOCSTR(PROD) \
"Low level module for connecting to " PROD " with a read/write interface\n"\
"inside transactions.\n"\
"\n"\
"This module is used to connect to the " PROD " transaction manager.\n"\
"The API described here has several purposes. We can use MAAPI when we wish\n"\
"to implement our own proprietary management agent.\n"\
"We also use MAAPI to attach to already existing " PROD " transactions, for\n"\
"example when we wish to implement semantic validation of configuration\n"\
"data in Python, and also when we wish to implement CLI wizards in Python.\n"\
"\n"\
"This documentation should be read together with the confd_lib_maapi(3) "\
"man page."

#define DOC(name) PyDoc_STRVAR(_maapi_ ## name ## __doc__,

/* ------------------------------------------------------------------------- */
DOC(connect)
/* ------------------------------------------------------------------------- */
"connect(sock, ip, port, path) -> None\n\n"

"Connect to the system daemon.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* ip -- the ip address\n"
"* port -- the port\n"
"* path -- the path if socket is AF_UNIX (optional)\n"
);

/* ------------------------------------------------------------------------- */
DOC(load_schemas)
/* ------------------------------------------------------------------------- */
"load_schemas(sock) -> None \n\n"

"Loads all schema information into the lib.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(load_schemas_list)
/* ------------------------------------------------------------------------- */
"load_schemas_list(sock, flags, nshash, nsflags) -> None\n\n"

"Loads selected schema information into the lib.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* flags -- the flags to set\n"
"* nshash -- the listed namespaces that schema information should be "
"loaded for\n"
"* nsflags -- namespace specific flags\n");

/* ------------------------------------------------------------------------- */
DOC(get_schema_file_path)
/* ------------------------------------------------------------------------- */
"get_schema_file_path(sock) -> str\n\n"

"If shared memory schema support has been enabled, this function will\n"
"return the pathname of the file used for the shared memory mapping,\n"
"which can then be passed to the mmap_schemas() function>\n\n"

"If creation of the schema file is in progress when the function\n"
"is called, the call will block until the creation has completed.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(close)
/* ------------------------------------------------------------------------- */
"close(sock) -> None \n\n"

"Ends session and closes socket.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(start_user_session)
/* ------------------------------------------------------------------------- */
"start_user_session(sock, username, context, groups, src_addr, "
"prot) -> None\n\n"

"Establish a user session on the socket.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* username -- the user for the session\n"
"* context -- context for the session\n"
"* groups -- groups\n"
"* src-addr -- src address of e.g. the client connecting\n"
"* prot -- the protocol used by the client for connecting\n");

/* ------------------------------------------------------------------------- */
DOC(start_user_session2)
/* ------------------------------------------------------------------------- */
"start_user_session2(sock, username, context, groups, src_addr, src_port,"
" prot) -> None\n\n"

"Establish a user session on the socket.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* username -- the user for the session\n"
"* context -- context for the session\n"
"* groups -- groups\n"
"* src-addr -- src address of e.g. the client connecting\n"
"* src-port -- src port of e.g. the client connecting\n"
"* prot -- the protocol used by the client for connecting\n");

/* ------------------------------------------------------------------------- */
DOC(start_user_session3)
/* ------------------------------------------------------------------------- */
"start_user_session3(sock, username, context, groups, src_addr, src_port,"
" prot, vendor, product, version, client_id) -> None\n\n"

"Establish a user session on the socket.\n\n"
"This function does the same as start_user_session2() but allows for\n"
"additional information to be passed to ConfD/NCS.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* username -- the user for the session\n"
"* context -- context for the session\n"
"* groups -- groups\n"
"* src-addr -- src address of e.g. the client connecting\n"
"* src-port -- src port of e.g. the client connecting\n"
"* prot -- the protocol used by the client for connecting\n"
"* vendor -- vendor string (may be None)\n"
"* product -- product string (may be None)\n"
"* version -- version string (may be None)\n"
"* client_id -- client identification string (may be None)");

/* ------------------------------------------------------------------------- */
DOC(end_user_session)
/* ------------------------------------------------------------------------- */
"end_user_session(sock) -> None\n\n"

"End the MAAPI user session associated with the socket\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(kill_user_session)
/* ------------------------------------------------------------------------- */
"kill_user_session(sock, usessid) -> None\n\n"

"Kill MAAPI user session with session id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- the MAAPI session id to be killed\n");

/* ------------------------------------------------------------------------- */
DOC(get_user_sessions)
/* ------------------------------------------------------------------------- */
"get_user_sessions(sock) -> list\n\n"

"Return a list of session ids.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(get_user_session)
/* ------------------------------------------------------------------------- */
"get_user_session(sock, usessid) -> " CONFD_PY_MODULE ".UserInfo\n\n"

"Return user info.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- session id\n");

/* ------------------------------------------------------------------------- */
DOC(get_my_user_session_id)
/* ------------------------------------------------------------------------- */
"get_my_user_session_id(sock) -> int\n\n"

"Returns user session id\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(set_user_session)
/* ------------------------------------------------------------------------- */
"set_user_session(sock, usessid) -> None\n\n"

"Associate a socket with an already existing user session.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- user session id\n");

/* ------------------------------------------------------------------------- */
DOC(get_user_session_identification)
/* ------------------------------------------------------------------------- */
"get_user_session_identification(sock, usessid) -> dict\n\n"

"Get user session identification data.\n\n"

"Get the user identification data related to a user session provided by the\n"
"'usessid' argument. The function returns a dict with the user\n"
"identification data.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- user session id\n");

/* ------------------------------------------------------------------------- */
DOC(get_user_session_opaque)
/* ------------------------------------------------------------------------- */
"get_user_session_opaque(sock, usessid) -> str\n\n"

"Returns a string containing additional 'opaque' information, if additional\n"
"'opaque' information is available.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- user session id\n");

/* ------------------------------------------------------------------------- */
DOC(set_next_user_session_id)
/* ------------------------------------------------------------------------- */
"set_next_user_session_id(sock, usessid) -> None\n\n"

"Set the user session id that will be assigned to the next user session\n"
"started. The given value is silently forced to be in the range 100 .. 2^31-1."
"\nThis function can be used to ensure that session ids for user sessions\n"
"started by northbound agents or via MAAPI are unique across a restart.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- user session id\n");

/* ------------------------------------------------------------------------- */
DOC(get_authorization_info)
/* ------------------------------------------------------------------------- */
"get_authorization_info(sock, usessid) -> "
    CONFD_PY_MODULE ".AuthorizationInfo\n\n"

"This function retrieves authorization info for a user session,"
"i.e. the groups that the user has been assigned to.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usessid -- user session id\n");

/* ------------------------------------------------------------------------- */
DOC(lock)
/* ------------------------------------------------------------------------- */
"lock(sock, name) -> None\n\n"

"Lock database with name.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the database to lock\n");

/* ------------------------------------------------------------------------- */
DOC(unlock)
/* ------------------------------------------------------------------------- */
"unlock(sock, name) -> None\n\n"

"Unlock database with name.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the database to unlock\n");

/* ------------------------------------------------------------------------- */
DOC(is_lock_set)
/* ------------------------------------------------------------------------- */
"is_lock_set(sock, name) -> int\n\n"

"Check if db name is locked. Return the 'usid' of the user holding the lock\n"
"or 0 if not locked.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(lock_partial)
/* ------------------------------------------------------------------------- */
"lock_partial(sock, name, xpaths) -> int\n\n"

"Lock a subset (xpaths) of database name. Returns lockid.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* xpaths -- a list of strings");

/* ------------------------------------------------------------------------- */
DOC(unlock_partial)
/* ------------------------------------------------------------------------- */
"unlock_partial(sock, lockid) -> None\n\n"

"Unlock a subset of a database which is locked by lockid.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* lockid -- id of the lock\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_validate)
/* ------------------------------------------------------------------------- */
"candidate_validate(sock) -> None\n\n"

"This function validates the candidate.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_commit)
/* ------------------------------------------------------------------------- */
"candidate_commit(sock) -> None \n\n"

"This function copies the candidate to running.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_confirmed_commit)
/* ------------------------------------------------------------------------- */
"candidate_confirmed_commit(sock, timeoutsecs) -> None\n\n"

"This function also copies the candidate into running. However if a call to\n"
"maapi_candidate_commit() is not done within timeoutsecs an automatic\n"
"rollback will occur.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* timeoutsecs -- timeout in seconds\n");

/* ------------------------------------------------------------------------- */
DOC(delete_config)
/* ------------------------------------------------------------------------- */
"delete_config(sock, name) -> None\n\n"

"Empties a datastore.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the datastore to empty\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_commit_persistent)
/* ------------------------------------------------------------------------- */
"candidate_commit_persistent(sock, persist_id) -> None\n\n"

"Confirm an ongoing persistent commit with the cookie given by persist_id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* persist_id -- gives the cookie for an already ongoing persistent "
"                confirmed commit\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_commit_info)
/* ------------------------------------------------------------------------- */
"candidate_commit_info(sock, persist_id, label, comment) -> None\n\n"

"Commit the candidate to running, or confirm an ongoing confirmed commit,\n"
"and set the Label and/or Comment that is stored in the rollback file when\n"
"the candidate is committed to running.\n\n"

"Note:\n"
">    To ensure the Label and/or Comment are stored in the rollback file in\n"
">    all cases when doing a confirmed commit, they must be given with both,\n"
">    the confirmed commit (using maapi_candidate_confirmed_commit_info())\n"
">    and the confirming commit (using this function).\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* persist_id -- gives the cookie for an already ongoing persistent "
"                confirmed commit\n"
"* label -- the Label\n"
"* comment -- the Comment\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_confirmed_commit_persistent)
/* ------------------------------------------------------------------------- */
"candidate_confirmed_commit_persistent(sock, timeoutsecs, persist, "
"persist_id) -> None\n\n"

"Start or extend a confirmed commit using persist id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* timeoutsecs -- timeout in seconds\n"
"* persist -- sets the cookie for the persistent confirmed commit\n"
"* persist_id -- gives the cookie for an already ongoing persistent "
"                confirmed commit\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_confirmed_commit_info)
/* ------------------------------------------------------------------------- */
"candidate_confirmed_commit_info(sock, timeoutsecs, persist, "
"persist_id, label, comment) -> None\n\n"

"Like candidate_confirmed_commit_persistent, but also allows for setting the\n"
"Label and/or Comment that is stored in the rollback file when the candidate\n"
"is committed to running.\n\n"

"Note:\n"
">    To ensure the Label and/or Comment are stored in the rollback file in\n"
">    all cases when doing a confirmed commit, they must be given with both,\n"
">    the confirmed commit (using this function) and the confirming commit\n"
">    (using candidate_commit_info()).\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* timeoutsecs -- timeout in seconds\n"
"* persist -- sets the cookie for the persistent confirmed commit\n"
"* persist_id -- gives the cookie for an already ongoing persistent "
"                confirmed commit\n"
"* label -- the Label\n"
"* comment -- the Comment\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_abort_commit)
/* ------------------------------------------------------------------------- */
"candidate_abort_commit(sock) -> None\n\n"

"Cancel an ongoing confirmed commit.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_abort_commit_persistent)
/* ------------------------------------------------------------------------- */
"candidate_abort_commit_persistent(sock, persist_id) -> None\n\n"

"Cancel an ongoing confirmed commit with the cookie given by persist_id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* persist_id -- gives the cookie for an already ongoing persistent "
"                confirmed commit\n");

/* ------------------------------------------------------------------------- */
DOC(candidate_reset)
/* ------------------------------------------------------------------------- */
"candidate_reset(sock) -> None\n\n"

"Copy running into candidate.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(confirmed_commit_in_progress)
/* ------------------------------------------------------------------------- */
"confirmed_commit_in_progress(sock) -> int\n\n"

"Checks whether a confirmed commit is ongoing. Returns a positive integer\n"
"being the usid of confirmed commit operation in progress or 0 if no\n"
"confirmed commit is in progress.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(copy_running_to_startup)
/* ------------------------------------------------------------------------- */
"copy_running_to_startup(sock) -> None\n\n"

"Copies running to startup.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(is_running_modified)
/* ------------------------------------------------------------------------- */
"is_running_modified(sock) -> bool\n\n"

"Checks if running is modified.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(is_candidate_modified)
/* ------------------------------------------------------------------------- */
"is_candidate_modified(sock) -> bool\n\n"

"Checks if candidate is modified.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(start_trans)
/* ------------------------------------------------------------------------- */
"start_trans(sock, name, readwrite) -> int\n\n"

"Creates a new transaction towards the data store specified by name, which\n"
"can be one of CONFD_CANDIDATE, CONFD_RUNNING, or CONFD_STARTUP (however\n"
"updating the startup data store is better done via\n"
"maapi_copy_running_to_startup()). The readwrite parameter can be either\n"
"CONFD_READ, to start a readonly transaction, or CONFD_READ_WRITE, to start\n"
"a read-write transaction. The function returns the transaction id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the database\n"
"* readwrite -- CONFD_READ or CONFD_WRITE\n");

/* ------------------------------------------------------------------------- */
DOC(start_trans2)
/* ------------------------------------------------------------------------- */
"start_trans2(sock, name, readwrite, usid) -> int\n\n"

"Start a transaction within an existing user session, returns the transaction\n"
"id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the database\n"
"* readwrite -- CONFD_READ or CONFD_WRITE\n"
"* usid -- user session id\n");

/* ------------------------------------------------------------------------- */
DOC(start_trans_flags)
/* ------------------------------------------------------------------------- */
"start_trans_flags(sock, name, readwrite, usid) -> int\n\n"

"The same as start_trans2, but can also set the same flags that 'set_flags'\n"
"can set.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the database\n"
"* readwrite -- CONFD_READ or CONFD_WRITE\n"
"* usid -- user session id\n"
"* flags -- same as for 'set_flags'\n" );

/* ------------------------------------------------------------------------- */
DOC(start_trans_flags2)
/* ------------------------------------------------------------------------- */
"start_trans_flags2(sock, name, readwrite, usid, vendor, product, version,\n"
" client_id) -> int\n\n"

"This function does the same as start_trans_flags() but allows for\n"
"additional information to be passed to ConfD/NCS.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* name -- name of the database\n"
"* readwrite -- CONFD_READ or CONFD_WRITE\n"
"* usid -- user session id\n"
"* flags -- same as for 'set_flags'\n"
"* vendor -- vendor string (may be None)\n"
"* product -- product string (may be None)\n"
"* version -- version string (may be None)\n"
"* client_id -- client identification string (may be None)");

/* ------------------------------------------------------------------------- */
DOC(start_trans_in_trans)
/* ------------------------------------------------------------------------- */
"start_trans_in_trans(sock, readwrite, usid, thandle) -> int\n\n"

"Start a transaction within an existing transaction, using the started\n"
"transaction as backend instead of an actual data store. Returns the\n"
"transaction id as an integer.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* readwrite -- CONFD_READ or CONFD_WRITE\n"
"* usid -- user session id\n"
"* thandle -- identifies the backend transaction to use\n");

/* ------------------------------------------------------------------------- */
DOC(finish_trans)
/* ------------------------------------------------------------------------- */
"finish_trans(sock, thandle) -> None\n\n"

"Finish a transaction.\n\n"

"If the transaction is implemented by an external database, this will invoke\n"
"the finish() callback.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(validate_trans)
/* ------------------------------------------------------------------------- */
"validate_trans(sock, thandle, unlock, forcevalidation) -> None\n\n"

"Validates all data written in a transaction.\n\n"

"If unlock is 1 (or True), the transaction is open for further editing even\n"
"if validation succeeds. If unlock is 0 (or False) and the function returns\n"
"CONFD_OK, the next function to be called MUST be maapi_prepare_trans() or\n"
"maapi_finish_trans().\n\n"

"unlock = 1 can be used to implement a 'validate' command which can be\n"
"given in the middle of an editing session. The first thing that happens is\n"
"that a lock is set. If unlock == 1, the lock is released on success. The\n"
"lock is always released on failure.\n\n"

"The forcevalidation argument should normally be 0 (or False). It has no\n"
"effect for a transaction towards the running or startup data stores,\n"
"validation is always performed. For a transaction towards the candidate\n"
"data store, validation will not be done unless forcevalidation is non-zero.\n"
"\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* unlock -- int or bool\n"
"* forcevalidation -- int or bool");


/* ------------------------------------------------------------------------- */
DOC(prepare_trans)
/* ------------------------------------------------------------------------- */
"prepare_trans(sock, thandle) -> None\n\n"

"First phase of a two-phase trans.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(prepare_trans_flags)
/* ------------------------------------------------------------------------- */
"prepare_trans_flags(sock, thandle, flags) -> None\n\n"

"First phase of a two-phase trans with flags.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- flags to set in the transaction\n");

/* ------------------------------------------------------------------------- */
DOC(commit_trans)
/* ------------------------------------------------------------------------- */
"commit_trans(sock, thandle) -> None\n\n"

"Final phase of a two phase transaction, committing the trans.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(abort_trans)
/* ------------------------------------------------------------------------- */
"abort_trans(sock, thandle) -> None\n\n"

"Final phase of a two phase transaction, aborting the trans.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(apply_trans)
/* ------------------------------------------------------------------------- */
"apply_trans(sock, thandle, keepopen) -> None\n\n"

"Apply a transaction.\n\n"

"Validates, prepares and eventually commits or aborts the transaction. If\n"
"the validation fails and the 'keep_open' argument is set to 1 or True, the\n"
"transaction is left open and the developer can react upon the validation\n"
"errors.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* keepopen -- if true, transaction is not discarded if validation fails");

/* ------------------------------------------------------------------------- */
DOC(apply_trans_flags)
/* ------------------------------------------------------------------------- */
"apply_trans_flags(sock, thandle, keepopen, flags) -> None\n\n"

"A variant of apply_trans() that takes an additional 'flags' argument.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* keepopen -- if true, transaction is not discarded if validation fails\n"
"* flags -- flags to set in the transaction\n");

/* ------------------------------------------------------------------------- */
DOC(get_rollback_id)
/* ------------------------------------------------------------------------- */
"get_rollback_id(sock, thandle) -> int\n\n"

"Get rollback id from a committed transaction. Returns int with fixed id,\n"
"where -1 indicates an error or no rollback id available.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(set_namespace)
/* ------------------------------------------------------------------------- */
"set_namespace(sock, thandle, hashed_ns) -> None\n\n"

"Indicate which namespace to use in case of ambiguities.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* hashed_ns -- the namespace to use\n");

/* ------------------------------------------------------------------------- */
DOC(cd)
/* ------------------------------------------------------------------------- */
"cd(sock, thandle, path) -> None\n\n"

"Change current position in the tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position to change to\n");

/* ------------------------------------------------------------------------- */
DOC(pushd)
/* ------------------------------------------------------------------------- */
"pushd(sock, thandle, path) -> None\n\n"

"Like cd, but saves the previous position in the tree. This can later be used\n"
"by popd to return.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position to change to\n");

/* ------------------------------------------------------------------------- */
DOC(popd)
/* ------------------------------------------------------------------------- */
"popd(sock, thandle) -> None\n\n"

"Return to earlier saved (pushd) position in the tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(getcwd)
/* ------------------------------------------------------------------------- */
"getcwd(sock, thandle) -> str\n\n"

"Get the current position in the tree as a string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(getcwd_kpath)
/* ------------------------------------------------------------------------- */
"getcwd_kpath(sock, thandle) -> " CONFD_PY_MODULE ".HKeypathRef\n\n"

"Get the current position in the tree as a HKeypathRef.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(exists)
/* ------------------------------------------------------------------------- */
"exists(sock, thandle, path) -> bool\n\n"

"Check wether a node in the data tree exists. Returns boolean.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position to check\n");

/* ------------------------------------------------------------------------- */
DOC(num_instances)
/* ------------------------------------------------------------------------- */
"num_instances(sock, thandle, path) -> int\n\n"

"Return the number of instances in a list in the tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position to check\n");

/* ------------------------------------------------------------------------- */
DOC(get_elem)
/* ------------------------------------------------------------------------- */
"get_elem(sock, thandle, path) -> " CONFD_PY_MODULE ".Value\n\n"

"Path must be a valid leaf node in the data tree. Returns a Value object.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position of elem\n");

/* ------------------------------------------------------------------------- */
DOC(init_cursor)
/* ------------------------------------------------------------------------- */
"init_cursor(sock, thandle, path) -> maapi.Cursor\n\n"

"Whenever we wish to iterate over the entries in a list in the data tree, we\n"
"must first initialize a cursor.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position of elem\n"
"* secondary_index -- name of secondary index to use (optional)\n"
"* xpath_expr -- xpath expression used to filter results (optional)\n");

/* ------------------------------------------------------------------------- */
DOC(get_next)
/* ------------------------------------------------------------------------- */
"get_next(mc) -> Union[List[" CONFD_PY_MODULE ".Value], bool]\n\n"

"Iterates and gets the keys for the next entry in a list. When no more keys\n"
"are found, False is returned.\n\n"

"Keyword arguments:\n\n"

"* mc -- maapiCursor\n\n");

/* ------------------------------------------------------------------------- */
DOC(find_next)
/* ------------------------------------------------------------------------- */
"find_next(mc, type, inkeys) -> "
    "Union[List[" CONFD_PY_MODULE ".Value], bool]\n\n"

"Update the cursor mc with the key(s) for the list entry designated by the\n"
"type and inkeys parameters. This function may be used to start a traversal\n"
"from an arbitrary entry in a list. Keys for subsequent entries may be\n"
"retrieved with the get_next() function. When no more keys are found, False\n"
"is returned.\n\n"

"The strategy to use is defined by type:\n\n"
"    FIND_NEXT - The keys for the first list entry after the one\n"
"                indicated by the inkeys argument.\n"
"    FIND_SAME_OR_NEXT - If the values in the inkeys array completely\n"
"                identifies an actual existing list entry, the keys for\n"
"                this entry are requested. Otherwise the same logic as\n"
"                for FIND_NEXT above.\n\n"

"Keyword arguments:\n\n"

"* mc -- maapiCursor\n"
"* type -- CONFD_FIND_NEXT or CONFD_FIND_SAME_OR_NEXT\n"
"* inkeys -- where to start finding\n");

/* ------------------------------------------------------------------------- */
DOC(destroy_cursor)
/* ------------------------------------------------------------------------- */
"destroy_cursor(mc) -> None\n\n"

"Deallocates memory which is associated with the cursor.\n\n"

"Keyword arguments:\n\n"

"* mc -- maapiCursor\n");

/* ------------------------------------------------------------------------- */
DOC(set_elem)
/* ------------------------------------------------------------------------- */
"set_elem(sock, thandle, v, path) -> None\n\n"

"Set element to confdValue.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* v -- confdValue\n"
"* path -- position of elem\n");

/* ------------------------------------------------------------------------- */
DOC(set_elem2)
/* ------------------------------------------------------------------------- */
"set_elem2(sock, thandle, strval, path) -> None\n\n"

"Set element to string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* strval -- confdValue\n"
"* path -- position of elem\n");

/* ------------------------------------------------------------------------- */
DOC(create)
/* ------------------------------------------------------------------------- */
"create(sock, thandle, path) -> None\n\n"

"Create a new list entry, a presence container or a leaf of type empty\n"
"in the data tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- path of item to create\n");

/* ------------------------------------------------------------------------- */
DOC(delete)
/* ------------------------------------------------------------------------- */
"delete(sock, thandle, path) -> None\n\n"

"Delete an existing list entry, a presence container or a leaf of type empty\n"
"from the data tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- path of item to delete\n");

/* ------------------------------------------------------------------------- */
DOC(get_object)
/* ------------------------------------------------------------------------- */
"get_object(sock, thandle, n, keypath) -> List[" CONFD_PY_MODULE ".Value]\n\n"

"Read at most n values from keypath in a list.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- position of list entry\n");

/* ------------------------------------------------------------------------- */
DOC(get_objects)
/* ------------------------------------------------------------------------- */
"get_objects(mc, n, nobj) -> List[" CONFD_PY_MODULE ".Value]\n\n"

"Read at most n values from each nobj lists starting at Cursor mc.\n"
"Returns a list of Value's.\n\n"

"Keyword arguments:\n\n"

"* mc -- maapiCursor\n"
"* n -- at most n values will be read\n"
"* nobj -- number of nobj lists which n elements will be taken from\n");

/* ------------------------------------------------------------------------- */
DOC(get_values)
/* ------------------------------------------------------------------------- */
"get_values(sock, thandle, values, keypath) -> list\n\n"

"Get values from keypath based on the Tag Value array values.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* values -- list of tagValues\n");

/* ------------------------------------------------------------------------- */
DOC(set_object)
/* ------------------------------------------------------------------------- */
"set_object(sock, thandle, values, keypath) -> None\n\n"

"Set leafs at path to object.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* values -- list of values\n"
"* keypath -- path to set\n");

/* ------------------------------------------------------------------------- */
DOC(set_values)
/* ------------------------------------------------------------------------- */
"set_values(sock, thandle, values, keypath) -> None\n\n"

"Set leafs at path to values.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* values -- list of tagValues\n"
"* keypath -- path to set\n");

/* ------------------------------------------------------------------------- */
DOC(get_case)
/* ------------------------------------------------------------------------- */
"get_case(sock, thandle, choice, keypath) -> " CONFD_PY_MODULE ".Value\n\n"

"Get the case from a YANG choice statement.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* choice -- choice name\n"
"* keypath -- path to choice\n");

/* ------------------------------------------------------------------------- */
DOC(get_attrs)
/* ------------------------------------------------------------------------- */
"get_attrs(sock, thandle, attrs, keypath) -> list\n\n"

"Get attributes for a node. Returns a list of attributes.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* attrs -- list of type of attributes to get\n"
"* keypath -- path to choice\n");

/* ------------------------------------------------------------------------- */
DOC(set_attr)
/* ------------------------------------------------------------------------- */
"set_attr(sock, thandle, attr, v, keypath) -> None\n\n"

"Set attributes for a node.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* attr -- attributes to set\n"
"* v -- value to set the attribute to\n"
"* keypath -- path to choice\n");


/* ------------------------------------------------------------------------- */
DOC(delete_all)
/* ------------------------------------------------------------------------- */
"delete_all(sock, thandle, how) -> None\n\n"

"Delete all data within a transaction.\n\n"

"The how argument specifies how to delete:\n"
"    DEL_SAFE - Delete everything except namespaces that were exported with\n"
"               tailf:export none. Top-level nodes that cannot be deleted\n"
"               due to AAA rules are left in place (descendant nodes may be\n"
"               deleted if the rules allow it).\n"
"   DEL_EXPORTED - As DEL_SAFE, but AAA rules are ignored.\n"
"   DEL_ALL - Delete everything, AAA rules are ignored.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* how -- DEL_SAFE, DEL_EXPORTED or DEL_ALL\n");

/* ------------------------------------------------------------------------- */
DOC(revert)
/* ------------------------------------------------------------------------- */
"revert(sock, thandle) -> None\n\n"

"Removes all changes done to the transaction.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(set_flags)
/* ------------------------------------------------------------------------- */
"set_flags(sock, thandle, flags) -> None\n\n"

"Modify read/write session aspect. See MAAPI_FLAG_xyz.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- flags to set\n");

/* ------------------------------------------------------------------------- */
DOC(set_delayed_when)
/* ------------------------------------------------------------------------- */
"set_delayed_when(sock, thandle, on) -> None\n\n"

"This function enables (on non-zero) or disables (on == 0) the 'delayed when'\n"
"mode of a transaction.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* on -- disables when on=0, enables for all other n\n");

/* ------------------------------------------------------------------------- */
DOC(set_label)
/* ------------------------------------------------------------------------- */
"set_label(sock, thandle, label) -> None\n\n"


"Set the Label that is stored in the rollback file when a transaction\n"
"towards running is committed.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* label -- the Label\n");

/* ------------------------------------------------------------------------- */
DOC(set_comment)
/* ------------------------------------------------------------------------- */
"set_comment(sock, thandle, comment) -> None\n\n"

"Set the Comment that is stored in the rollback file when a transaction\n"
"towards running is committed.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* comment -- the Comment\n");

/* ------------------------------------------------------------------------- */
DOC(copy)
/* ------------------------------------------------------------------------- */
"copy(sock, from_thandle, to_thandle) -> None\n\n"

"Copy all data from one data store to another.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* from_thandle -- transaction handle\n"
"* to_thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(copy_path)
/* ------------------------------------------------------------------------- */
"copy_path(sock, from_thandle, to_thandle, path) -> None\n\n"

"Copy subtree rooted at path from one data store to another.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* from_thandle -- transaction handle\n"
"* to_thandle -- transaction handle\n"
"* path -- the subtree rooted at path is copied\n");


/* ------------------------------------------------------------------------- */
DOC(copy_tree)
/* ------------------------------------------------------------------------- */
"copy_tree(sock, thandle, frompath, topath) -> None\n\n"

"Copy subtree rooted at frompath to topath.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* frompath -- the subtree rooted at path is copied\n"
"* topath -- to which path the subtree is copied\n");

/* ------------------------------------------------------------------------- */
DOC(insert)
/* ------------------------------------------------------------------------- */
"insert(sock, thandle, path) -> None\n\n"

"Insert a new entry in a list, the key of the list must be a integer.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- the subtree rooted at path is copied\n");

/* ------------------------------------------------------------------------- */
DOC(move)
/* ------------------------------------------------------------------------- */
"move(sock, thandle, tokey, path) -> None\n\n"

"Moves an existing list entry, i.e. renames the entry using the tokey\n"
"parameter.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* tokey -- confdValue list\n"
"* path -- the subtree rooted at path is copied\n");

/* ------------------------------------------------------------------------- */
DOC(move_ordered)
/* ------------------------------------------------------------------------- */
"move_ordered(sock, thandle, where, tokey, path) -> None\n\n"

"Moves an entry in an 'ordered-by user' statement to a new position.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* where -- FIRST, LAST, BEFORE or AFTER\n"
"* tokey -- confdValue list\n"
"* path -- the subtree rooted at path is copied\n");

/* ------------------------------------------------------------------------- */
DOC(authenticate)
/* ------------------------------------------------------------------------- */
"authenticate(sock, user, password, n) -> tuple\n\n"

"Authenticate a user session. Use the 'n' to get a list of n-1 groups that\n"
"the user is a member of. Use n=1 if the function is used in a context\n"
"where the group names are not needed. Returns 1 if accepted without groups.\n"
"If the authentication failed or was accepted a tuple with first element\n"
"status code, 0 for rejection and 1 for accepted is returned. The second\n"
"element either contains the reason for the rejection as a string OR a list\n"
"groupnames.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* user -- username\n"
"* pass -- password\n"
"* n -- number of groups to return\n");

/* ------------------------------------------------------------------------- */
DOC(authenticate2)
/* ------------------------------------------------------------------------- */
"authenticate2(sock, user, password, src_addr, src_port, context, prot, n) ->"
" tuple\n\n"

"This function does the same thing as maapi.authenticate(), but allows for\n"
"passing of the additional parameters src_addr, src_port, context, and prot,\n"
"which otherwise are passed only to maapi_start_user_session()/\n"
"maapi_start_user_session2(). The parameters are passed on to an external\n"
"authentication executable.\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* user -- username\n"
"* pass -- password\n"
"* src_addr -- ip address\n"
"* src_port -- port number\n"
"* context -- context for the session\n"
"* prot -- the protocol used by the client for connecting\n"
"* n -- number of groups to return\n");

/* ------------------------------------------------------------------------- */
DOC(attach)
/* ------------------------------------------------------------------------- */
"attach(sock, hashed_ns, ctx) -> None\n\n"

"Attach to a existing transaction.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* hashed_ns -- the namespace to use\n"
"* ctx -- transaction context\n");

/* ------------------------------------------------------------------------- */
DOC(attach2)
/* ------------------------------------------------------------------------- */
"attach2(sock, hashed_ns, usid, thandle) -> None\n\n"

"Used when there is no transaction context beforehand, to attach to a\n"
"existing transaction.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* hashed_ns -- the namespace to use\n"
"* usid -- user session id, can be set to 0 to use the owner of the transaction"
"\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(attach_init)
/* ------------------------------------------------------------------------- */
"attach_init(sock) -> int\n\n"

"Attach the _MAAPI socket to the special transaction available during phase0.\n"
"Returns the thandle as an integer.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(detach)
/* ------------------------------------------------------------------------- */
"detach(sock, ctx) -> None\n\n"

"Detaches an attached _MAAPI socket.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* ctx -- transaction context\n");


/* ------------------------------------------------------------------------- */
DOC(detach2)
/* ------------------------------------------------------------------------- */
"detach2(sock, thandle) -> None\n\n"

"Detaches an attached _MAAPI socket when we do not have a transaction context\n"
"available.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(diff_iterate)
/* ------------------------------------------------------------------------- */
"diff_iterate(sock, thandle, iter, flags) -> None\n\n"

"Iterate through a transaction diff.\n\n"

"For each diff in the transaction the callback function 'iter' will be\n"
"called. The iter function needs to have the following signature:\n\n"

"    def iter(keypath, operation, oldvalue, newvalue)\n\n"

"Where arguments are:\n\n"

"* keypath - the affected path (HKeypathRef)\n"
"* operation - one of MOP_CREATED, MOP_DELETED, MOP_MODIFIED, MOP_VALUE_SET,\n"
"              MOP_MOVED_AFTER, or MOP_ATTR_SET\n"
"* oldvalue - always None\n"
"* newvalue - see below\n\n"

"The 'newvalue' argument may be set for operation MOP_VALUE_SET and is a\n"
"Value object in that case. For MOP_MOVED_AFTER it may be set to a list of\n"
"key values identifying an entry in the list - if it's None the list entry\n"
"has been moved to the beginning of the list. For MOP_ATTR_SET it will be\n"
"set to a 2-tuple of Value's where the first Value is the attribute set\n"
"and the second Value is the value the attribute was set to. If the\n"
"attribute has been deleted the second value is of type C_NOEXISTS\n\n"

"The iter function should return one of:\n\n"

"* ITER_STOP - Stop further iteration\n"
"* ITER_RECURSE - Recurse further down the node children\n"
"* ITER_CONTINUE - Ignore node children and continue with the node's siblings\n"
"\n"
"One could also define a class implementing the call function as:\n\n"

"    class DiffIterator(object):\n"
"        def __init__(self):\n"
"            self.count = 0\n"
"\n"
"        def __call__(self, kp, op, oldv, newv):\n"
"            print('kp={0}, op={1}, oldv={2}, newv={3}'.format(\n"
"                str(kp), str(op), str(oldv), str(newv)))\n"
"            self.count += 1\n"
"            return _confd.ITER_RECURSE\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* iter -- iterator function, will be called for every diff in the transaction"
"\n"
"* flags -- bitmask of ITER_WANT_ATTR and ITER_WANT_P_CONTAINER");

/* ------------------------------------------------------------------------- */
DOC(keypath_diff_iterate)
/* ------------------------------------------------------------------------- */
"keypath_diff_iterate(sock, thandle, iter, flags, path) -> "
"None\n\n"

"Like diff_iterate but takes an additional path argument.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* iter -- iterator function, will be called for every diff in the transaction"
"\n"
"* flags -- bitmask of ITER_WANT_ATTR and ITER_WANT_P_CONTAINER\n"
"* path -- receive only changes from this path and below");

/* ------------------------------------------------------------------------- */
DOC(iterate)
/* ------------------------------------------------------------------------- */
"iterate(sock, thandle, iter, flags, path) -> None\n\n"

"Used to iterate over all the data in a transaction and the underlying data\n"
"store as opposed to only iterate over changes like diff_iterate.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* iter -- iterator function, will be called for every diff in the transaction"
"\n"
"* flags -- ITER_WANT_ATTR or 0\n"
"* path -- receive only changes from this path and below\n\n"

"The iter callback function should have the following signature:\n\n"

"    def my_iterator(kp, v, attr_vals)");

/* ------------------------------------------------------------------------- */
DOC(get_running_db_status)
/* ------------------------------------------------------------------------- */
"get_running_db_status(sock) -> int\n\n"

"If a transaction fails in the commit() phase, the configuration database is\n"
"in in a possibly inconsistent state. This function queries ConfD on the\n"
"consistency state. Returns 1 if the configuration is consistent and 0\n"
"otherwise.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(set_running_db_status)
/* ------------------------------------------------------------------------- */
"set_running_db_status(sock, status) -> None\n\n"

"Sets the notion of consistent state of the running db.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* status -- integer status to set\n");

/* ------------------------------------------------------------------------- */
DOC(list_rollbacks)
/* ------------------------------------------------------------------------- */
"list_rollbacks(sock, rp_size) -> list\n\n"

"Get a list of rollbacks, at most rp_size big.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* rp_size -- maximum number of rollback files to list\n");

/* ------------------------------------------------------------------------- */
DOC(load_rollback)
/* ------------------------------------------------------------------------- */
"load_rollback(sock, thandle, rollback_num) -> None\n\n"

"Install a rollback file with number 'rollback_num'.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* rollback_num -- rollback file no\n");

/* ------------------------------------------------------------------------- */
DOC(load_rollback_fixed)
/* ------------------------------------------------------------------------- */
"load_rollback_fixed(sock, thandle, fixed_num) -> None\n\n"

"Install a rollback file with fixed number 'fixed_num'.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* fixed_num -- rollback fixed number\n");

/* ------------------------------------------------------------------------- */
DOC(request_action)
/* ------------------------------------------------------------------------- */
"request_action(sock, params, hashed_ns, path) -> list\n\n"

"Invoke an action defined in the data model. Returns a list of"
"tagValues.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* params -- tagValue parameters for the action\n"
"* hashed_ns -- namespace\n"
"* path -- path to action\n");

/* ------------------------------------------------------------------------- */
DOC(request_action_th)
/* ------------------------------------------------------------------------- */
"request_action_th(sock, thandle, params, path) -> list\n\n"

"Same as for request_action() but uses the current namespace.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* params -- tagValue parameters for the action\n"
"* path -- path to action\n");


/* ------------------------------------------------------------------------- */
DOC(request_action_str_th)
/* ------------------------------------------------------------------------- */
"request_action_str_th(sock, thandle, cmd, path) -> str\n\n"

"The same as request_action_th but takes the parameters as a string and\n"
"returns the result as a string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* cmd -- string parameters\n"
"* path -- path to action\n");


/* ------------------------------------------------------------------------- */
DOC(xpath2kpath)
/* ------------------------------------------------------------------------- */
"xpath2kpath(sock, xpath) -> " CONFD_PY_MODULE ".HKeypathRef\n\n"

"Convert an xpath to a hashed keypath.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* xpath -- to convert\n");
/* ------------------------------------------------------------------------- */
DOC(xpath2kpath_th)
/* ------------------------------------------------------------------------- */
"xpath2kpath_th(sock, thandle, xpath) -> " CONFD_PY_MODULE ".HKeypathRef\n\n"

"Convert an xpath to a hashed keypath.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* xpath -- to convert\n");

/* ------------------------------------------------------------------------- */
DOC(user_message)
/* ------------------------------------------------------------------------- */
"user_message(sock, to, message, sender) -> None\n\n"

"Send a message to a specific user.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* to -- user to send message to or 'all' to send to all users\n"
"* message -- the message\n"
"* sender -- send as\n");

/* ------------------------------------------------------------------------- */
DOC(sys_message)
/* ------------------------------------------------------------------------- */
"sys_message(sock, to, message) -> None\n\n"

"Send a message to a specific user, a specific session or all user depending\n"
"on the 'to' parameter. 'all', <session-id> or <user-name> can be used.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* to -- user to send message to or 'all' to send to all users\n"
"* message -- the message\n");

/* ------------------------------------------------------------------------- */
DOC(prio_message)
/* ------------------------------------------------------------------------- */
"prio_message(sock, to, message) -> None\n\n"

"Like sys_message but will be output directly instead of delivered when the\n"
"receiver terminates any ongoing command.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* to -- user to send message to or 'all' to send to all users\n"
"* message -- the message\n");

/* ------------------------------------------------------------------------- */
DOC(cli_diff_cmd)
/* ------------------------------------------------------------------------- */
"cli_diff_cmd(sock, thandle, thandle_old, flags, path, size) -> str\n\n"

"Get the diff between two sessions as a series C/I cli commands. Returns a\n"
"string. If no changes exist between the two sessions for the given path a\n"
_TM ".error.Error will be thrown with the error set to ERR_BADPATH\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* thandle_old -- transaction handle\n"
"* flags -- as for cli_path_cmd\n"
"* path -- as for cli_path_cmd\n"
"* size -- limit diff\n");

/* ------------------------------------------------------------------------- */
DOC(cli_accounting)
/* ------------------------------------------------------------------------- */
"cli_accounting(sock, user, usid, cmdstr) -> None\n\n"

"Generates an audit log entry in the CLI audit log.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* user -- user to generate the entry for\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(cli_path_cmd)
/* ------------------------------------------------------------------------- */
"cli_path_cmd(sock, thandle, flags, path, size) -> str\n\n"

"Returns string of the C/I CLI command that can be associated with the given\n"
"path. The flags can be given as FLAG_EMIT_PARENTS to enable the commands to\n"
"reach the submode for the path to be emitted. The flags can be given as\n"
"FLAG_DELETE to emit the command to delete the given path. The flags can be\n"
"given as FLAG_NON_RECURSIVE to prevent that  all children to a container or\n"
"list item are displayed.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- as above\n"
"* path -- the path for the cmd\n"
"* size -- limit cmd\n");

/* ------------------------------------------------------------------------- */
DOC(cli_cmd_to_path)
/* ------------------------------------------------------------------------- */
"cli_cmd_to_path(sock, line, nsize, psize) -> tuple\n\n"

"Returns string of the C/I namespaced CLI path that can be associated with\n"
"the given command. Returns a tuple ns and path. \n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* line -- data model path as string\n"
"* nsize -- limit length of namespace\n"
"* psize -- limit length of path\n");

/* ------------------------------------------------------------------------- */
DOC(cli_cmd_to_path2)
/* ------------------------------------------------------------------------- */
"cli_cmd_to_path2(sock, thandle, line, nsize, psize) -> tuple\n\n"

"Returns string of the C/I namespaced CLI path that can be associated with\n"
"the given command. In the context of the provided transaction handle.\n"
"Returns a tuple ns and path.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* line -- data model path as string\n"
"* nsize -- limit length of namespace\n"
"* psize -- limit length of path\n");

/* ------------------------------------------------------------------------- */
DOC(cli_write)
/* ------------------------------------------------------------------------- */
"cli_write(sock, usess, buf) -> None\n\n"

"Write to the cli.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* buf -- string to write\n");

/* ------------------------------------------------------------------------- */
DOC(cli_cmd)
/* ------------------------------------------------------------------------- */
"cli_cmd(sock, usess, buf) -> None\n\n"

"Execute CLI command in the ongoing CLI session.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* buf -- string to write\n");

/* ------------------------------------------------------------------------- */
DOC(cli_cmd2)
/* ------------------------------------------------------------------------- */
"cli_cmd2(sock, usess, buf, flags) -> None\n\n"

"Execute CLI command in a ongoing CLI session. With flags:\n"
"CMD_NO_FULLPATH - Do not perform the fullpath check on show commands.\n"
"CMD_NO_HIDDEN - Allows execution of hidden CLI commands.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* buf -- string to write\n"
"* flags -- as above\n" );

/* ------------------------------------------------------------------------- */
DOC(cli_cmd3)
/* ------------------------------------------------------------------------- */
"cli_cmd3(sock, usess, buf, flags, unhide) -> None\n\n"

"Execute CLI command in a ongoing CLI session.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* buf -- string to write\n"
"* flags -- as above\n"
"* unhide -- The unhide parameter is used for passing a hide group which is\n"
"    unhidden during the execution of the command.\n");

/* ------------------------------------------------------------------------- */
DOC(cli_cmd4)
/* ------------------------------------------------------------------------- */
"cli_cmd4(sock, usess, buf, flags, unhide) -> None\n\n"

"Execute CLI command in a ongoing CLI session.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* buf -- string to write\n"
"* flags -- as above\n"
"* unhide -- The unhide parameter is used for passing a hide group which is\n"
"    unhidden during the execution of the command.\n");

/* ------------------------------------------------------------------------- */
DOC(cli_set)
/* ------------------------------------------------------------------------- */
"cli_set(sock, usess, opt, value) -> None\n\n"

"Set CLI session parameter.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* opt -- option to set\n"
"* value -- the new value of the session parameter\n");

/* ------------------------------------------------------------------------- */
DOC(cli_get)
/* ------------------------------------------------------------------------- */
"cli_get(sock, usess, opt, size) -> str\n\n"

"Read CLI session parameter or attribute.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* opt -- option to get\n"
"* size -- maximum response size (optional, default 1024)\n");

/* ------------------------------------------------------------------------- */
DOC(set_readonly_mode)
/* ------------------------------------------------------------------------- */
"set_readonly_mode(sock, flag) -> None\n\n"

"Control if northbound agents should be able to write or not.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* flag -- non-zero means read-only mode\n");

/* ------------------------------------------------------------------------- */
DOC(disconnect_remote)
/* ------------------------------------------------------------------------- */
"disconnect_remote(sock, address) -> None\n\n"

"Disconnect all remote connections to 'address' except HA connections.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* address -- ip address (string)\n");

/* ------------------------------------------------------------------------- */
DOC(disconnect_sockets)
/* ------------------------------------------------------------------------- */
"disconnect_sockets(sock, sockets) -> None\n\n"

"Disconnect 'sockets' which is a list of sockets (fileno).\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* sockets -- list of sockets (int)\n");

/* ------------------------------------------------------------------------- */
DOC(cli_prompt)
/* ------------------------------------------------------------------------- */
"cli_prompt(sock, usess, prompt, echo, size) -> str\n\n"

"Prompt user for a string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* usess -- user session\n"
"* prompt -- string to show the user\n"
"* echo -- determines wether to control if the input should be echoed or not.\n"
"    ECHO shows the input, NOECHO does not\n"
"* size -- maximum response size (optional, default 1024)\n");

/* TODO: should we implement these? */
/* ------------------------------------------------------------------------- */
DOC(cli_prompt_oneof)
/* ------------------------------------------------------------------------- */
"Prompt user for a string.");

/* ------------------------------------------------------------------------- */
DOC(cli_prompt_oneof2)
/* ------------------------------------------------------------------------- */
"Prompt user for a string.");

/* TODO: should we implement these? */
/* ------------------------------------------------------------------------- */
DOC(cli_read_eof)
/* ------------------------------------------------------------------------- */
"Prompt user for a string.");

/* ------------------------------------------------------------------------- */
DOC(cli_read_eof2)
/* ------------------------------------------------------------------------- */
"Prompt user for a string.");

/* ------------------------------------------------------------------------- */
DOC(save_config)
/* ------------------------------------------------------------------------- */
"save_config(sock, thandle, flags, path) -> int\n\n"

"Save the config, returns an id.\n"
"The flags parameter controls the saving as follows. The value is a bitmask.\n"
"\n"
"        CONFIG_XML -- The configuration format is XML.\n"
"        CONFIG_XML_PRETTY -- The configuration format is pretty printed XML.\n"
"        CONFIG_JSON -- The configuration is in JSON format.\n"
"        CONFIG_J -- The configuration is in curly bracket Juniper CLI\n"
"            format.\n"
"        CONFIG_C -- The configuration is in Cisco XR style format.\n"
"        CONFIG_TURBO_C -- The configuration is in Cisco XR style format.\n"
"            A faster parser than the normal CLI will be used.\n"
"        CONFIG_C_IOS -- The configuration is in Cisco IOS style format.\n"
"        CONFIG_XPATH -- The path gives an XPath filter instead of a\n"
"            keypath. Can only be used with CONFIG_XML and\n"
"            CONFIG_XML_PRETTY.\n"
"        CONFIG_WITH_DEFAULTS -- Default values are part of the\n"
"            configuration dump.\n"
"        CONFIG_SHOW_DEFAULTS -- Default values are also shown next to\n"
"            the real configuration value. Applies only to the CLI formats.\n"
"        CONFIG_WITH_OPER -- Include operational data in the dump.\n"
"        CONFIG_HIDE_ALL -- Hide all hidden nodes.\n"
"        CONFIG_UNHIDE_ALL -- Unhide all hidden nodes.\n"
#ifdef CONFD_PY_PRODUCT_NCS
"        CONFIG_WITH_SERVICE_META -- Include NCS service-meta-data\n"
"            attributes(refcounter, backpointer, and original-value) in the\n"
"            dump.\n"
#endif
"        CONFIG_NO_PARENTS -- When a path is provided its parent nodes are by\n"
"            default included. With this option the output will begin\n"
"            immediately at path - skipping any parents.\n"
"        CONFIG_OPER_ONLY -- Include only operational data, and ancestors to\n"
"            operational data nodes, in the dump.\n"
"        CONFIG_NO_BACKQUOTE -- This option can only be used together with\n"
"            CONFIG_C and CONFIG_C_IOS. When set backslash will not be quoted\n"
"            in strings.\n"
"        CONFIG_CDB_ONLY -- Include only data stored in CDB in the dump. By\n"
"            default only configuration data is included, but the flag can be\n"
"            combined with either CONFIG_WITH_OPER or CONFIG_OPER_ONLY to\n"
"            save both configuration and operational data, or only\n"
"            operational data, respectively.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- as above\n"
"* path -- save only configuration below path\n");

/* ------------------------------------------------------------------------- */
DOC(save_config_result)
/* ------------------------------------------------------------------------- */
"save_config_result(sock, id) -> None\n\n"

"Verify that we received the entire configuration over the stream socket.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* id -- the id returned from save_config\n");

/* ------------------------------------------------------------------------- */
DOC(load_config)
/* ------------------------------------------------------------------------- */
"load_config(sock, thandle, flags, filename) -> None\n\n"

"Loads configuration from 'filename'.\n"
"The caller of the function has to indicate which format the file has by\n"
"using one of the following flags:\n\n"
"        CONFIG_XML -- XML format\n"
"        CONFIG_J -- Juniper curly bracket style\n"
"        CONFIG_C -- Cisco XR style\n"
"        CONFIG_TURBO_C -- A faster version of CONFIG_C\n"
"        CONFIG_C_IOS -- Cisco IOS style\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- a transaction handle\n"
"* flags -- as above\n"
"* filename -- to read the configuration from\n");

/* ------------------------------------------------------------------------- */
DOC(load_config_cmds)
/* ------------------------------------------------------------------------- */
"load_config_cmds(sock, thandle, flags, cmds, path) -> None\n\n"

"Loads configuration from the string 'cmds'\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- a transaction handle\n"
"* cmds -- a string of cmds\n"
"* flags -- as above\n");

/* ------------------------------------------------------------------------- */
DOC(load_config_stream)
/* ------------------------------------------------------------------------- */
"load_config_stream(sock, th, flags) -> int\n\n"

"Loads configuration from the stream socket. The th and flags parameters are\n"
"the same as for load_config(). Returns and id.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- a transaction handle\n"
"* flags -- as for load_config()\n");

/* ------------------------------------------------------------------------- */
DOC(load_config_stream_result)
/* ------------------------------------------------------------------------- */
"load_config_stream_result(sock, id) -> int\n\n"

"We use this function to verify that the configuration we wrote on the\n"
"stream socket was successfully loaded.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* id -- the id returned from load_config_stream()\n");

/* ------------------------------------------------------------------------- */
DOC(roll_config)
/* ------------------------------------------------------------------------- */
"roll_config(sock, thandle, path) -> int\n\n"

"This function can be used to save the equivalent of a rollback file for a\n"
"given configuration before it is committed (or a subtree thereof) in curly\n"
"bracket format. Returns an id\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- tree for which to save the rollback configuration\n");

/* ------------------------------------------------------------------------- */
DOC(roll_config_result)
/* ------------------------------------------------------------------------- */
"roll_config_result(sock, id) -> int\n\n"

"We use this function to assert that we received the entire rollback\n"
"configuration over a stream socket.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* id -- the id returned from roll_config()\n");

/* ------------------------------------------------------------------------- */
DOC(get_stream_progress)
/* ------------------------------------------------------------------------- */
"get_stream_progress(sock, id) -> int\n\n"

"Used in conjunction with a maapi stream to see how much data has been\n"
"consumed.\n\n"

"This function allows us to limit the amount of data 'in flight' between the\n"
"application and the system. The sock parameter must be the maapi socket\n"
"used for a function call that required a stream socket for writing\n"
"(currently the only such function is load_config_stream()), and the id\n"
"parameter is the id returned by that function.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* id -- the id returned from load_config_stream()\n");

/* ------------------------------------------------------------------------- */
DOC(xpath_eval_expr)
/* ------------------------------------------------------------------------- */
"xpath_eval_expr(sock, thandle, expr, trace, path) -> str\n\n"

"Like xpath_eval but returns a string.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* expr -- the XPath Path expression to evaluate\n"
"* trace -- a trace function that takes a string as a parameter\n"
"* path -- the context node\n");

/* ------------------------------------------------------------------------- */
DOC(xpath_eval)
/* ------------------------------------------------------------------------- */
"xpath_eval(sock, thandle, expr, result, trace, path) -> None\n\n"

"Evaluate the xpath expression in 'expr'. For each node in the  resulting\n"
"node the function 'result' is called with the keypath to the resulting\n"
"node as the first argument and, if the node is a leaf and has a value. the\n"
"value of that node as the second argument. For each invocation of 'result'\n"
"the function should return ITER_CONTINUE to tell the XPath evaluator to\n"
"continue or ITER_STOP to stop the evaluation. A trace function, 'pytrace',\n"
"could be supplied and will be called with a single string as an argument.\n"
"'None' can be used if no trace is needed. Unless a 'path' is given the\n"
"root node will be used as a context for the evaluations.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* expr -- the XPath Path expression to evaluate\n"
"* result -- the result function\n"
"* trace -- a trace function that takes a string as a parameter\n"
"* path -- the context node\n");

/* ------------------------------------------------------------------------- */
DOC(query_start)
/* ------------------------------------------------------------------------- */
"query_start(sock, thandle, expr, context_node, chunk_size, initial_offset,\n"
"            result_as, select, sort) -> int\n\n"

"Starts a new query attached to the transaction given in 'th'.\n"
"Returns a query handle.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* expr -- the XPath Path expression to evaluate\n"
"* context_node -- The context node (an ikeypath) for the primary expression,\n"
"    or None (which means that the context node will be /).\n"
"* chunk_size --  How many results to return at a time. If set to 0,\n"
"    a default number will be used.\n"
"* initial_offset -- Which result in line to begin with (1 means to start\n"
"    from the beginning).\n"
"* result_as -- The format the results will be returned in.\n"
"* select -- An array of XPath 'select' expressions.\n"
"* sort -- An array of XPath expressions which will be used for sorting\n");

/* ------------------------------------------------------------------------- */
DOC(query_result)
/* ------------------------------------------------------------------------- */
"query_result(sock, qh) -> " CONFD_PY_MODULE ".QueryResult\n\n"

"Fetches the next available chunk of results associated with query handle\n"
"qh.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* qh -- query handle\n");

/* ------------------------------------------------------------------------- */
DOC(query_result_count)
/* ------------------------------------------------------------------------- */
"query_result_count(sock, qh) -> int\n\n"

"Counts the number of query results\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* qh -- query handle\n");

/* ------------------------------------------------------------------------- */
DOC(query_free_result)
/* ------------------------------------------------------------------------- */
"query_free_result(qrs) -> None\n\n"

"Deallocates the struct returned by 'query_result()'.\n\n"

"Keyword arguments:\n\n"

"* qrs -- the query result structure to free\n");

/* ------------------------------------------------------------------------- */
DOC(query_reset_to)
/* ------------------------------------------------------------------------- */
"query_reset_to(sock, qh, offset) -> None\n\n"

"Reset the query to offset.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* qh -- query handle\n"
"* offset -- offset counted from the beginning\n");

/* ------------------------------------------------------------------------- */
DOC(query_reset)
/* ------------------------------------------------------------------------- */
"query_reset(sock, qh) -> None\n\n"

"Reset the query to the beginning again.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* qh -- query handle\n");

/* ------------------------------------------------------------------------- */
DOC(query_stop)
/* ------------------------------------------------------------------------- */
"query_stop(sock, qh) -> None\n\n"

"Stop the running query.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* qh -- query handle\n");


/* ------------------------------------------------------------------------- */
DOC(do_display)
/* ------------------------------------------------------------------------- */
"do_display(sock, thandle, path) -> int\n\n"

"If the data model uses the YANG when or tailf:display-when statement, this\n"
"function can be used to determine if the item given by 'path' should\n"
"be displayed or not.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- path to the 'display-when' statement\n");

/* ------------------------------------------------------------------------- */
DOC(install_crypto_keys)
/* ------------------------------------------------------------------------- */
"install_crypto_keys(sock) -> None\n\n"

"Copy configured DES3 and AES keys into the memory in the library.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(init_upgrade)
/* ------------------------------------------------------------------------- */
"init_upgrade(sock, timeoutsecs, flags) -> None\n\n"

"First step in an upgrade, initializes the upgrade procedure.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* timeoutsecs -- maximum time to wait for user to voluntarily exit from\n"
"    'configuration' mode\n"
"* flags -- 0 or 'UPGRADE_KILL_ON_TIMEOUT' (will terminate all ongoing\n"
"    transactions\n");

/* ------------------------------------------------------------------------- */
DOC(perform_upgrade)
/* ------------------------------------------------------------------------- */
"perform_upgrade(sock, loadpathdirs) -> None\n\n"

"Second step in an upgrade. Loads new data model files.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* loadpathdirs -- list of directories that are searched for CDB 'init' files"
"\n");

/* ------------------------------------------------------------------------- */
DOC(commit_upgrade)
/* ------------------------------------------------------------------------- */
"commit_upgrade(sock) -> None\n\n"

"Final step in an upgrade.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(abort_upgrade)
/* ------------------------------------------------------------------------- */
"abort_upgrade(sock) -> None\n\n"

"Can be called before committing upgrade in order to abort it.\n\n"

"Final step in an upgrade.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(aaa_reload)
/* ------------------------------------------------------------------------- */
"aaa_reload(sock, synchronous) -> None\n\n"

"Start a reload of aaa from external data provider.\n\n"

"Used by external data provider to notify that there is a change to the AAA\n"
"data. Calling the function with the argument 'synchronous' set to 1 or True\n"
"means that the call will block until the loading is completed.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* synchronous -- if 1, will wait for the loading complete and return when\n"
"    the loading is complete; if 0, will only initiate the loading of AAA\n"
"    data and return immediately\n");

/* ------------------------------------------------------------------------- */
DOC(aaa_reload_path)
/* ------------------------------------------------------------------------- */
"aaa_reload_path(sock, synchronous, path) -> None\n\n"

"Start a reload of aaa from external data provider.\n\n"

"A variant of _maapi_aaa_reload() that causes only the AAA subtree given by\n"
"path to be loaded.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* synchronous -- if 1, will wait for the loading complete and return when\n"
"    the loading is complete; if 0, will only initiate the loading of AAA\n"
"    data and return immediately\n"
"* path -- the subtree to be loaded\n");

/* ------------------------------------------------------------------------- */
DOC(snmpa_reload)
/* ------------------------------------------------------------------------- */
"snmpa_reload(sock, synchronous) -> None\n\n"

"Start a reload of SNMP Agent config from external data provider.\n\n"

"Used by external data provider to notify that there is a change to the SNMP\n"
"Agent config data. Calling the function with the argument 'synchronous' set\n"
"to 1 or True means that the call will block until the loading is completed.\n"
"\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* synchronous -- if 1, will wait for the loading complete and return when\n"
"    the loading is complete; if 0, will only initiate the loading and return\n"
"    immediately\n");

/* ------------------------------------------------------------------------- */
DOC(start_phase)
/* ------------------------------------------------------------------------- */
"start_phase(sock, phase, synchronous) -> None\n\n"

"When the system has been started in phase0, this function tells the system\n"
"to proceed to start phase 1 or 2.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* phase -- phase to start, 1 or 2\n"
"* synchronous -- if 1, will wait for the loading complete and return when\n"
"    the loading is complete; if 0, will only initiate the loading of AAA\n"
"    data and return immediately\n");

/* ------------------------------------------------------------------------- */
DOC(wait_start)
/* ------------------------------------------------------------------------- */
"wait_start(sock, phase) -> None\n\n"

"Wait for the system to reach a certain start phase (0,1 or 2).\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* phase -- phase to wait for, 0, 1 or 2\n");

/* ------------------------------------------------------------------------- */
DOC(reload_config)
/* ------------------------------------------------------------------------- */
"reload_config(sock) -> None\n\n"

"Request that the system reloads its configuration files.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(reopen_logs)
/* ------------------------------------------------------------------------- */
"reopen_logs(sock) -> None\n\n"

"Request that the system closes and re-opens its log files.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(stop)
/* ------------------------------------------------------------------------- */
"stop(sock) -> None\n\n"

"Request that the system stops.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(rebind_listener)
/* ------------------------------------------------------------------------- */
"rebind_listener(sock, listener) -> None\n\n"

"Request that the subsystems specified by 'listeners' rebinds its listener\n"
"socket(s).\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* listener -- One of the following parameters (ORed together if more than one)"
"\n\n"
"        LISTENER_IPC  \n"
"        LISTENER_NETCONF\n"
"        LISTENER_SNMP\n"
"        LISTENER_CLI\n"
"        LISTENER_WEBUI\n");

/* ------------------------------------------------------------------------- */
DOC(clear_opcache)
/* ------------------------------------------------------------------------- */
"clear_opcache(sock, path) -> None\n\n"

"Clearing of operational data cache.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* path -- the path to the subtree to clear\n");

/* ------------------------------------------------------------------------- */
DOC(cs_node_cd)
/* ------------------------------------------------------------------------- */
"cs_node_cd(socket, thandle, path) -> "
    "Union[" CONFD_PY_MODULE ".CsNode, None]\n\n"

"Utility function which finds the resulting CsNode given a string keypath.\n\n"

"Does the same thing as " _TM ".cs_node_cd(), but can handle paths that are \n"
"ambiguous due to traversing a mount point, by sending a request to the\n"
"daemon\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* path -- the keypath\n");

/* ------------------------------------------------------------------------- */
DOC(cs_node_children)
/* ------------------------------------------------------------------------- */
"cs_node_children(sock, thandle, mount_point, path) -> "
    "List[" CONFD_PY_MODULE ".CsNode]\n\n"

"Retrieve a list of the children nodes of the node given by mount_point\n"
"that are valid for path. The mount_point node must be a mount point\n"
"(i.e. mount_point.is_mount_point() == True), and the path must lead to\n"
"a specific instance of this node (including the final keys if mount_point\n"
"is a list node). The thandle parameter is optional, i.e. it can be given\n"
"as -1 if a transaction is not available.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* mount_point -- a CsNode instance\n"
"* path -- the path to the instance of the node\n");

/* ------------------------------------------------------------------------- */
DOC(report_progress)
/* ------------------------------------------------------------------------- */
"report_progress(sock, verbosity, msg) -> None\n\n"

"Report progress events.\n\n"

"This function makes it possible to report transaction/action progress\n"
"from user code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n");

/* ------------------------------------------------------------------------- */
DOC(report_progress_start)
/* ------------------------------------------------------------------------- */
"report_progress_start(sock, verbosity, msg, package) -> int\n\n"

"Report progress events.\n"
"Used for calculation of the duration between two events.\n\n"

"This function makes it possible to report transaction/action progress\n"
"from user code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* package -- from what package the message is reported (only NCS)\n");

/* ------------------------------------------------------------------------- */
DOC(report_progress_stop)
/* ------------------------------------------------------------------------- */
"report_progress_stop(sock, verbosity, msg, annotation,\n"
"                     package, timestamp) -> int\n\n"

"Report progress events.\n"
"Used for calculation of the duration between two events.\n\n"

"This function makes it possible to report transaction/action progress\n"
"from user code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* annotation -- metadata about the event, indicating error, explains latency\n"
"    or shows result etc\n"
"* package -- from what package the message is reported (only NCS)\n"
"* timestamp -- start of the event\n");

/* ------------------------------------------------------------------------- */
DOC(netconf_ssh_call_home)
/* ------------------------------------------------------------------------- */
"netconf_ssh_call_home(sock, host, port) -> None\n\n"

"Initiates a NETCONF SSH Call Home connection.\n\n"

"Keyword arguments:\n\n"
"sock -- a python socket instance\n"
"host -- an ipv4 addres, ipv6 address, or host name\n"
"port -- the port to connect to\n");

/* ------------------------------------------------------------------------- */
DOC(netconf_ssh_call_home_opaque)
/* ------------------------------------------------------------------------- */
"netconf_ssh_call_home_opaque(sock, host, opaque, port) -> None\n\n"

"Initiates a NETCONF SSH Call Home connection.\n\n"

"Keyword arguments:\n"
"sock -- a python socket instance\n"
"host -- an ipv4 addres, ipv6 address, or host name\n"
"opaque -- opaque string passed to an external call home session\n"
"port -- the port to connect to\n");

#ifdef CONFD_PY_PRODUCT_NCS

/* ------------------------------------------------------------------------- */
DOC(shared_create)
/* ------------------------------------------------------------------------- */
"shared_create(sock, thandle, flags, path) -> None\n\n"

"FASTMAP version of create.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- Must be set as 0\n");

/* ------------------------------------------------------------------------- */
DOC(shared_set_elem)
/* ------------------------------------------------------------------------- */
"shared_set_elem(sock, thandle, v, flags, path) -> None\n\n"

"FASTMAP version of set_elem.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* v -- the value to set\n"
"* flags -- should be 0\n"
"* path -- the path to the element to set\n");

/* ------------------------------------------------------------------------- */
DOC(shared_set_elem2)
/* ------------------------------------------------------------------------- */
"shared_set_elem2(sock, thandle, strval, flags, path) -> None\n\n"

"FASTMAP version of set_elem2.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* strval -- the value to se\n"
"* flags -- should be 0\n"
"* path -- the path to the element to set\n");

/* ------------------------------------------------------------------------- */
DOC(shared_set_values)
/* ------------------------------------------------------------------------- */
"shared_set_values(sock, thandle, values, flags, keypath) -> None\n\n"

"FASTMAP version of set_values.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* values -- list of tagValues\n"
"* flags -- should be 0\n"
"* keypath -- path to set\n");

/* ------------------------------------------------------------------------- */
DOC(shared_insert)
/* ------------------------------------------------------------------------- */
"shared_insert(sock, thandle, flags, path) -> None\n\n"

"FASTMAP version of insert.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- Must be set as 0\n"
"* path -- the path to the list to insert a new entry into\n");

/* ------------------------------------------------------------------------- */
DOC(shared_copy_tree)
/* ------------------------------------------------------------------------- */
"shared_copy_tree(sock, thandle, flags, frompath, topath) -> None\n\n"

"FASTMAP version of copy_tree.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* flags -- Must be set as 0\n"
"* frompath -- the path to copy the tree from\n"
"* topath -- the path to copy the tree to\n");

/* ------------------------------------------------------------------------- */
DOC(apply_template)
/* ------------------------------------------------------------------------- */
"apply_template(sock, thandle, template, variables, flags, rootpath) -> "
"None\n\n"

"Apply a template that has been loaded into NCS. The template parameter gives\n"
"the name of the template. This is NOT a FASTMAP function, for that use\n"
"shared_ncs_apply_template instead.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* template -- template name\n"
"* variables -- None or a list of variables in the form of tuples\n"
"* flags -- should be 0\n"
"* rootpath -- in what context to apply the template\n");

/* ------------------------------------------------------------------------- */
DOC(shared_apply_template)
/* ------------------------------------------------------------------------- */
"shared_apply_template(sock, thandle, template, variables,"
"flags, rootpath) -> None\n\n"

"FASTMAP version of ncs_apply_template.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* template -- template name\n"
"* variables -- None or a list of variables in the form of tuples\n"
"* flags -- Must be set as 0\n"
"* rootpath -- in what context to apply the template\n");

/* ------------------------------------------------------------------------- */
DOC(get_templates)
/* ------------------------------------------------------------------------- */
"get_templates(sock) -> list\n\n"

"Get the defined templates.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n");

/* ------------------------------------------------------------------------- */
DOC(write_service_log_entry)
/* ------------------------------------------------------------------------- */
"write_service_log_entry(sock, path, msg, type, level) -> None\n\n"

"Write service log entries.\n\n"

"This function makes it possible to write service log entries from\n"
"FASTMAP code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* path -- service instance path\n"
"* msg -- message to log\n"
"* type -- log entry type\n"
"* level -- log entry level\n");

/* ------------------------------------------------------------------------- */
DOC(report_progress2)
/* ------------------------------------------------------------------------- */
"report_progress2(sock, verbosity, msg, package) -> None\n\n"

"Report progress events.\n\n"

"This function makes it possible to report transaction/action progress\n"
"from user code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* package -- from what package the message is reported\n");

/* ------------------------------------------------------------------------- */
DOC(report_service_progress)
/* ------------------------------------------------------------------------- */
"report_service_progress(sock, verbosity, msg, path) -> None\n\n"

"Report progress events for a service.\n\n"

"This function makes it possible to report transaction progress\n"
"from FASTMAP code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* path -- service instance path\n");

/* ------------------------------------------------------------------------- */
DOC(report_service_progress2)
/* ------------------------------------------------------------------------- */
"report_service_progress2(sock, verbosity, msg, package, path) -> None\n\n"

"Report progress events for a service.\n\n"

"This function makes it possible to report transaction progress\n"
"from FASTMAP code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* package -- from what package the message is reported\n"
"* path -- service instance path\n");

/* ------------------------------------------------------------------------- */
DOC(report_service_progress_start)
/* ------------------------------------------------------------------------- */
"report_service_progress_start(sock, verbosity, msg, package, path) -> int\n\n"

"Report progress events for a service.\n"
"Used for calculation of the duration between two events.\n\n"

"This function makes it possible to report transaction progress\n"
"from FASTMAP code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* package -- from what package the message is reported\n"
"* path -- service instance path\n");

/* ------------------------------------------------------------------------- */
DOC(report_service_progress_stop)
/* ------------------------------------------------------------------------- */
"report_service_progress_stop(sock, verbosity, msg, annotation,\n"
"                             package, path) -> None\n\n"

"Report progress events for a service.\n"
"Used for calculation of the duration between two events.\n\n"

"This function makes it possible to report transaction progress\n"
"from FASTMAP code.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* verbosity -- at which verbosity level the message should be reported\n"
"* msg -- message to report\n"
"* annotation -- metadata about the event, indicating error, explains latency\n"
"    or shows result etc\n"
"* package -- from what package the message is reported\n"
"* path -- service instance path\n"
"* timestamp -- start of the event\n");

/* ------------------------------------------------------------------------- */
DOC(apply_trans_params)
/* ------------------------------------------------------------------------- */
"apply_trans_params(sock, thandle, keepopen, params) -> list\n\n"

"A variant of apply_trans() that takes commit parameters in form of a list of"
"TagValue objects and returns a list of TagValue objects depending on the"
"parameters passed in.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* keepopen -- if true, transaction is not discarded if validation fails\n"
"* params -- list of TagValue objects\n"
);

/* ------------------------------------------------------------------------- */
DOC(get_trans_params)
/* ------------------------------------------------------------------------- */
"get_trans_params(sock, thandle) -> list\n\n"

"Get the commit parameters for a transaction. The commit parameters are\n"
"returned as a list of TagValue objects.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n");

/* ------------------------------------------------------------------------- */
DOC(commit_queue_result)
/* ------------------------------------------------------------------------- */
"commit_queue_result(sock, thandle, timeoutsecs) -> tuple\n\n"

"Get result from commit queue. Returns tuple(int, int) containing queue id\n"
"and status.\n\n"

"Keyword arguments:\n\n"

"* sock -- a python socket instance\n"
"* thandle -- transaction handle\n"
"* timeoutsecs -- timeout in seconds\n");



#endif /* CONFD_PY_PRODUCT_NCS */
