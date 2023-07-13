/*
 * dp documentation to be included in _dp.c
 */

#define LIB_MODULE_DOCSTR(PROD) \
"Common functions for applications connecting to " PROD ".\n"\
"\n"\
"The module is used to connect to " PROD ". It describes functions and data\n"\
"structures that are not specific to any of the APIs described in the\n"\
"submodules.\n"\
"\n"\
"This documentation should be read together with the confd_lib_lib(3) man page."

#define LIB_MODULE_DOCSTR_NCS \
"\n"\
"\n"\
"N.B. If a custom NCS listening port is set with the environment variable\n"\
"NCS_IPC_PORT, the constant _ncs.PORT will be set to that value."

#define DOC(name) PyDoc_STRVAR(_confd_ ## name ## __doc__,

/* ------------------------------------------------------------------------- */
DOC(init)
/* ------------------------------------------------------------------------- */
"init(name, file, level) -> None\n\n"

"Initializes the ConfD library. Must be called before any other NCS API\n"
"functions are called. There should be no need to call this function\n"
"directly. It is called internally when the Python module is loaded.\n\n"

"Keyword arguments:\n\n"

"* name -- e\n"
"* file -- (optional)\n"
"* level -- (optional)"
);

/* ------------------------------------------------------------------------- */
DOC(set_debug)
/* ------------------------------------------------------------------------- */
"set_debug(level, file) -> None\n\n"

"Sets the debug level\n\n"

"Keyword arguments:\n\n"

"* file -- (optional)\n"
"* level -- (optional)"
);

/* ------------------------------------------------------------------------- */
DOC(pp_kpath)
/* ------------------------------------------------------------------------- */
"pp_kpath(hkeypath) -> str\n\n"

"Utility function which pretty prints a string representation of the path\n"
"hkeypath. This will use the NCS curly brace notation, i.e.\n"
"\"/servers/server{www}/ip\". Requires that schema information is available\n"
"to the library.\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance"
);

/* ------------------------------------------------------------------------- */
DOC(pp_kpath_len)
/* ------------------------------------------------------------------------- */
"pp_kpath_len(hkeypath, len) -> str\n\n"

"A variant of pp_kpath() that prints only the first len elements of hkeypath."
"\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a _lib.HKeypathRef instance\n"
"* len -- number of elements to print"
);

/* ------------------------------------------------------------------------- */
DOC(stream_connect)
/* ------------------------------------------------------------------------- */
"stream_connect(sock, id, flags, ip, port, path) -> None\n\n"

"Connects a stream socket to NCS.\n\n"

"Keyword arguments:\n\n"

"* sock -- a Python socket instance\n"
"* id -- id\n"
"* flags -- flags\n"
"* ip -- ip address - if sock family is AF_INET or AF_INET6 (optional)\n"
"* port -- port - if sock family is AF_INET or AF_INET6 (optional)\n"
"* path -- a filename - if sock family is AF_UNIX (optional)"
);

/* ------------------------------------------------------------------------- */
DOC(find_cs_root)
/* ------------------------------------------------------------------------- */
"find_cs_root(ns) -> Union[CsNode, None]\n\n"

"When schema information is available to the library, this function returns\n"
"the root of the tree representaton of the namespace given by ns for the\n"
"(first) toplevel node. For namespaces that are augmented into other\n"
"namespaces such that they do not have a toplevel node, this function returns\n"
"None - the nodes of such a namespace are found below the augment target\n"
"node(s) in other tree(s).\n\n"

"Keyword arguments:\n\n"

"* ns -- the namespace id"
);

/* ------------------------------------------------------------------------- */
DOC(cs_node_cd)
/* ------------------------------------------------------------------------- */
"cs_node_cd(start, path) -> Union[CsNode, None]\n\n"

"Utility function which finds the resulting CsNode given an (optional)\n"
"starting node and a (relative or absolute) string keypath.\n\n"

"Keyword arguments:\n\n"

"* start -- a CsNode instance or None\n"
"* path -- the path"
);

/* ------------------------------------------------------------------------- */
DOC(find_ns_type)
/* ------------------------------------------------------------------------- */
"find_ns_type(nshash, name) -> Union[CsType, None]\n\n"

"Returns a CsType type definition for the type named name, which is defined\n"
"in the namespace identified by nshash, or None if the type could not be\n"
"found. If nshash is 0, the type name will be looked up among the built-in\n"
"types (i.e. the YANG built-in types, the types defined in the YANG\n"
"\"tailf-common\" module, and the types defined in the \"confd\" and \"xs\"\n"
"namespaces).\n\n"

"Keyword arguments:\n\n"

"* nshash -- a namespace hash or 0 (0 searches for built-in types)\n"
"* name -- the name of the type"
);

/* ------------------------------------------------------------------------- */
DOC(ns2prefix)
/* ------------------------------------------------------------------------- */
"ns2prefix(ns) -> Union[str, None]\n\n"

"Returns a string giving the namespace prefix for the namespace ns, if the\n"
"namespace is known to the library - otherwise it returns None.\n\n"

"Keyword arguments:\n\n"

"* ns -- a namespace hash"
);

/* ------------------------------------------------------------------------- */
DOC(hash2str)
/* ------------------------------------------------------------------------- */
"hash2str(hash) -> Union[str, None]\n\n"

"Returns a string representing the node name given by hash, or None if the\n"
"hash value is not found. Requires that schema information has been loaded\n"
"from the NCS daemon into the library - otherwise it always returns None.\n\n"

"Keyword arguments:\n\n"

"* hash -- a hash"
);

/* ------------------------------------------------------------------------- */
DOC(mmap_schemas)
/* ------------------------------------------------------------------------- */
"mmap_schemas(filename) -> None\n\n"

"If shared memory schema support has been enabled, this function will\n"
"will map a shared memory segment into the current process address space\n"
"and make it ready for use.\n\n"

"The filename can be obtained by using the get_schema_file_path() function\n\n"

"The filename argument specifies the pathname of the file that is used as\n"
"backing store.\n\n"

"Keyword arguments:\n\n"

"* filename -- a filename string");

/* ------------------------------------------------------------------------- */
DOC(str2hash)
/* ------------------------------------------------------------------------- */
"str2hash(str) -> int\n\n"

"Returns the hash value representing the node name given by str, or 0 if the\n"
"string is not found.  Requires that schema information has been loaded from\n"
"the NCS daemon into the library - otherwise it always returns 0.\n\n"

"Keyword arguments:\n\n"

"* str -- a name string"
);

/* ------------------------------------------------------------------------- */
DOC(fatal)
/* ------------------------------------------------------------------------- */
"fatal(str) -> None\n\n"

"Utility function which formats a string, prints it to stderr and exits with\n"
"exit code 1. This function will never return.\n\n"

"Keyword arguments:\n\n"

"* str -- a message string"
);

/* ------------------------------------------------------------------------- */
DOC(decrypt)
/* ------------------------------------------------------------------------- */
"decrypt(ciphertext) -> str\n\n"

"When data is read over the CDB interface, the MAAPI interface or received\n"
"in event notifications, the data for the two builtin types\n"
"tailf:des3-cbc-encrypted-string or tailf:aes-cfb-128-encrypted-string is\n"
"encrypted. This function decrypts ciphertext and returns the clear text as\n"
"a string.\n\n"

"Keyword arguments:\n\n"

"* ciphertext -- encrypted string\n"
);

/* ------------------------------------------------------------------------- */
DOC(find_cs_node)
/* ------------------------------------------------------------------------- */
"find_cs_node(hkeypath, len) -> Union[CsNode, None]\n\n"

"Utility function which finds the CsNode corresponding to the len first\n"
"elements of the hashed keypath. To make the search consider the full\n"
"keypath leave out the len parameter.\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance\n"
"* len -- number of elements to return (optional)"
);

/* ------------------------------------------------------------------------- */
DOC(find_cs_node_child)
/* ------------------------------------------------------------------------- */
"find_cs_node_child(parent, xmltag) -> Union[CsNode, None]\n\n"

"Utility function which finds the CsNode corresponding to the child node\n"
"given as xmltag.\n\n"

"See confd_find_cs_node_child() in confd_lib_lib(3).\n\n"

"Keyword arguments:\n\n"

"* parent -- the parent CsNode\n"
"* xmltag -- the child node"
);

/* ------------------------------------------------------------------------- */
DOC(hkp_tagmatch)
/* ------------------------------------------------------------------------- */
"hkp_tagmatch(hkeypath, tags) -> int\n\n"

"When checking the hkeypaths that get passed into each iteration in e.g.\n"
"cdb_diff_iterate() we can either explicitly check the paths, or use this\n"
"function to do the job. The tags list (typically statically initialized)\n"
"specifies a tagpath to match against the hkeypath. See cdb_diff_match().\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance\n"
"* tags -- a list of XmlTag instances"
);

/* ------------------------------------------------------------------------- */
DOC(hkp_prefix_tagmatch)
/* ------------------------------------------------------------------------- */
"hkp_prefix_tagmatch(hkeypath, tags) -> bool\n\n"

"A simplified version of hkp_tagmatch() - it returns True if the tagpath\n"
"matches a prefix of the hkeypath, i.e. it is equivalent to calling\n"
"hkp_tagmatch() and checking if the return value includes CONFD_HKP_MATCH_TAGS."
"\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance\n"
"* tags -- a list of XmlTag instances"
);

/* ------------------------------------------------------------------------- */
DOC(hkeypath_dup)
/* ------------------------------------------------------------------------- */
"hkeypath_dup(hkeypath) -> HKeypathRef\n\n"

"Duplicates a HKeypathRef object.\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance"
);

/* ------------------------------------------------------------------------- */
DOC(hkeypath_dup_len)
/* ------------------------------------------------------------------------- */
"hkeypath_dup_len(hkeypath, len) -> HKeypathRef\n\n"

"Duplicates the first len elements of hkeypath.\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance\n"
"* len -- number of elements to include in the copy"
);

/* ------------------------------------------------------------------------- */
DOC(max_object_size)
/* ------------------------------------------------------------------------- */
"max_object_size(object) -> int\n\n"

"Utility function which returns the maximum size (i.e. the needed length of\n"
"the confd_value_t array) for an \"object\" retrieved by cdb_get_object(),\n"
"maapi_get_object(), and corresponding multi-object functions.\n\n"

"Keyword arguments:\n\n"

"* object -- the CsNode"
);

/* ------------------------------------------------------------------------- */
DOC(next_object_node)
/* ------------------------------------------------------------------------- */
"next_object_node(object, cur, value) -> Union[CsNode, None]\n\n"

"Utility function to allow navigation of the confd_cs_node schema tree in\n"
"parallel with the confd_value_t array populated by cdb_get_object(),\n"
"maapi_get_object(), and corresponding multi-object functions.\n\n"

"The cur parameter is the CsNode for the current value, and the value\n"
"parameter is the current value in the array. The function returns a CsNode\n"
"for the next value in the array, or None when the complete object has been\n"
"traversed. In the initial call for a given traversal, we must pass\n"
"self.children() for the cur parameter - this always points to the CsNode\n"
"for the first value in the array.\n\n"

"Keyword arguments:\n\n"

"* object -- CsNode of the list container node\n"
"* cur -- The CsNode of the current value\n"
"* value -- The current value"
);

/* ------------------------------------------------------------------------- */
DOC(get_leaf_list_type)
/* ------------------------------------------------------------------------- */
"get_leaf_list_type(node) -> CsType\n\n"

"For a leaf-list node, the type() method in the CsNodeInfo identifies a\n"
"\"list type\" for the leaf-list \"itself\". This function returns the type\n"
"of the elements in the leaf-list, i.e. corresponding to the type\n"
"substatement for the leaf-list in the YANG module.\n\n"

"Keyword arguments:\n\n"

"* node -- The CsNode of the leaf-list\n"
);

/* ------------------------------------------------------------------------- */
DOC(get_nslist)
/* ------------------------------------------------------------------------- */
"get_nslist() -> list\n\n"

"Provides a list of the namespaces known to the library as a list of\n"
"five-tuples. Each tuple contains the the namespace hash (int), the prefix\n"
"(string), the namespace uri (string), the revision (string), and the\n"
"module name (string).\n\n"

"If schemas are not loaded an empty list will be returned."
);

/* ------------------------------------------------------------------------- */
DOC(xpath_pp_kpath)
/* ------------------------------------------------------------------------- */
"xpath_pp_kpath(hkeypath) -> str\n\n"

"Utility function which pretty prints a string representation of the path\n"
"hkeypath. This will format the path as an XPath, i.e.\n"
"\"/servers/server[name=\"www\"']/ip\". Requires that schema information is\n"
"available to the library.\n\n"

"Keyword arguments:\n\n"

"* hkeypath -- a HKeypathRef instance"
);

/* ------------------------------------------------------------------------- */
DOC(expr_op2str)
/* ------------------------------------------------------------------------- */
"expr_op2str(op) -> str\n\n"

"Convert confd_expr_op value to a string.\n\n"

"Keyword arguments:\n\n"

"* op -- confd_expr_op integer value"
);

/* ------------------------------------------------------------------------- */
DOC(list_filter_type2str)
/* ------------------------------------------------------------------------- */
"list_filter_type2str(op) -> str\n\n"

"Convert confd_list_filter_type value to a string.\n\n"

"Keyword arguments:\n\n"

"* type -- confd_list_filter_type integer value"
);

#ifdef CONFD_PY_PRODUCT_NCS

/* ------------------------------------------------------------------------- */
DOC(set_kill_child_on_parent_exit)
/* ------------------------------------------------------------------------- */
"set_kill_child_on_parent_exit() -> bool\n\n"

"Instruct the operating system to kill this process if the parent process\n"
"exits."
);

/* ------------------------------------------------------------------------- */
DOC(internal_connect)
/* ------------------------------------------------------------------------- */
"internal_connect(id, sock, ip, port, path) -> None\n\n"

"Internal function used by NCS Python VM."
);
#endif /* CONFD_PY_PRODUCT_NCS */

#ifdef CONFD_PY_EXT_API_TIMING

/* ------------------------------------------------------------------------- */
DOC(ext_api_timing)
/* ------------------------------------------------------------------------- */
"ext_api_timing() -> dict\n\n"

"Get Python and C library timing statistics."
);

#endif /* CONFD_PY_EXT_API_TIMING */

#undef DOC
