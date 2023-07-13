/*
 * dp documentation to be included in _ha.c
 */

#define HA_MODULE_DOCSTR(PROD) \
"Low level module for connecting to " PROD " HA subsystem.\n"\
"\n"\
"This module is used to connect to the " PROD " High Availability (HA)\n"\
"subsystem. " PROD " can replicate the configuration data on several nodes\n"\
"in a cluster. The purpose of this API is to manage the HA\n"\
"functionality. The details on usage of the HA API are described in the\n"\
"chapter High availability in the User Guide.\n"\
"\n"\
"This documentation should be read together with the confd_lib_ha(3) man page."

#define DOC(name) PyDoc_STRVAR(_ha_ ## name ## __doc__,

/* ------------------------------------------------------------------------- */
DOC(connect)
/* ------------------------------------------------------------------------- */
"connect(sock, token, ip, port, pstr) -> None\n\n"

"Connect a HA socket which can be used to control a NCS HA node. The token\n"
"is a secret string that must be shared by all participants in the cluster.\n"
"There can only be one HA socket towards NCS. A new call to\n"
"ha_connect() makes NCS close the previous connection and reset the token to\n"
"the new value.\n\n"

"Keyword arguments:\n\n"

"* sock -- a Python socket instance\n"
"* token -- secret string\n"
"* ip -- the ip address if socket is AF_INET or AF_INET6 (optional)\n"
"* port -- the port if socket is AF_INET or AF_INET6 (optional)\n"
"* pstr -- a filename if socket is AF_UNIX (optional)."
);

/* ------------------------------------------------------------------------- */
DOC(beprimary)
/* ------------------------------------------------------------------------- */
"beprimary(sock, mynodeid) -> None\n\n"

"Instruct a HA node to be primary and also give the node a name.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected HA socket\n"
"* mynodeid -- name of the node (Value or string)"
);

/* ------------------------------------------------------------------------- */
DOC(besecondary)
/* ------------------------------------------------------------------------- */
"besecondary(sock, mynodeid, primary_id, primary_ip, waitreply) -> None\n\n"

"Instruct a NCS HA node to be a secondary node with a named primary node.\n"
"If waitreply is True the function is synchronous and it will hang until the\n"
"node has initialized its CDB database. This may mean that the CDB database\n"
"is copied in its entirety from the primary node. If False, we do not wait\n"
"for the reply, but it is possible to use a notifications socket and get\n"
"notified asynchronously via a HA_INFO_BESECONDARY_RESULT notification.\n"
"In both cases, it is also possible to use a notifications socket and get\n"
"notified asynchronously when CDB at the secondary node is initialized.\n\n"

"Keyword arguments:\n\n"

"* sock       -- a previously connected HA socket\n"
"* mynodeid   -- name of this secondary node (Value or string)\n"
"* primary_id -- name of the primary node (Value or string)\n"
"* primary_ip -- ip address of the primary node\n"
"* waitreply  -- synchronous or not (bool)"
);

/* ------------------------------------------------------------------------- */
DOC(benone)
/* ------------------------------------------------------------------------- */
"benone(sock) -> None\n\n"

"Instruct a node to resume the initial state, i.e. neither become primary\n"
"nor secondary.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected HA socket"
);

/* ------------------------------------------------------------------------- */
DOC(berelay)
/* ------------------------------------------------------------------------- */
"berelay(sock) -> None\n\n"

"Instruct an established HA secondary node to be a relay for other\n"
"secondary nodes.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected HA socket"
);

/* ------------------------------------------------------------------------- */
DOC(status)
/* ------------------------------------------------------------------------- */
"status(sock) -> None\n\n"

"Query a ConfD HA node for its status.\n\n"

"Returns a 2-tuple of the HA status of the node in the format\n"
"(State,[list_of_nodes]) where 'list_of_nodes' is the primary/secondary(s)\n"
"connected with node.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected HA socket"
);

/* ------------------------------------------------------------------------- */
DOC(secondary_dead)
/* ------------------------------------------------------------------------- */
"secondary_dead(sock, nodeid) -> None\n\n"

"This function must be used by the application to inform NCS HA subsystem\n"
"that another node which is possibly connected to NCS is dead.\n\n"

"Keyword arguments:\n\n"

"* sock -- a previously connected HA socket\n"
"* nodeid -- name of the node (Value or string)"
);

/* ------------------------------------------------------------------------- */
// BIASED FREE: Backwards compatibility - remove later
DOC(bemaster)
"bemaster(sock, mynodeid) -> None\n\n"

"This function is deprecated and will be removed.\n"
"Use beprimary() instead."
);

DOC(beslave)
"beslave(sock, mynodeid, primary_id, primary_ip, waitreply) -> None\n\n"

"This function is deprecated and will be removed.\n"
"Use besecondary() instead."
);

DOC(slave_dead)
"slave_dead(sock, nodeid) -> None\n\n"

"This function is deprecated and will be removed.\n"
"Use secondary_dead() instead."
);
/* ------------------------------------------------------------------------- */

#undef DOC
