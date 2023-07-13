/*
 * Copyright 2013 Tail-F Systems AB
 */

// include first, order is significant to get defines correct
#include "confdpy_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#if defined(CONFD_PY_PRODUCT_NCS) && defined(HAVE_SYS_PRCTL_H)
#include <sys/prctl.h>
#include <signal.h>
#endif /* defined(CONFD_PY_PRODUCT_NCS) && defined(HAVE_SYS_PRCTL_H) */

#include <confd.h>

#include "confdpy_err.h"
#include "types.h"

#include "common.h"

#define INITIAL_BUF_SIZE 1024

/* ************************************************************************ */
/* confd_lib API functions                                                  */
/* ************************************************************************ */

/* ************************************************************************ */
/* confd_lib */

static FILE *g_debug_stream = NULL;

static int set_debug_stream(PyObject *f)
{
    if (g_debug_stream) {
        if (g_debug_stream != stdin &&
            g_debug_stream != stdout &&
            g_debug_stream != stderr) {
                fclose(g_debug_stream);
        }
        g_debug_stream = NULL;
    }

    if (f && f != Py_None) {
        PyObject *ret = PyObject_CallMethod(f, "fileno", NULL);
        if (ret == NULL) {
            PyErr_Format(PyExc_TypeError, "Unable to get file descriptor "
                                          "by calling fileno() on provided "
                                          "file argument.");
            return 0;
        }
        int fd = (int)PyLong_AsLong(ret);
        Py_DECREF(ret);

        if (fd == 0) {
            g_debug_stream = stdin;
        }
        else if (fd == 1) {
            g_debug_stream = stdout;
        }
        else if (fd == 2) {
            g_debug_stream = stderr;
        }
        else {
            g_debug_stream = fdopen(fd, "a");
        }
    }
    return 1;
}

EXT_API_FUN(_confd_init, EXT_API_FUN_LIB_INIT)
{
    static char *kwlist[] = { "name", "file", "level", NULL };
    enum confd_debug_level dbglvl = CONFD_SILENT;
    PyObject *f = NULL;
    char *name = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|Oi", kwlist,
                &name, &f, &dbglvl)) {
        return NULL;
    }
    if (!set_debug_stream(f)) {
        return NULL;
    }
    CONFD_EXEC(confd_init(name, g_debug_stream, dbglvl));
    Py_RETURN_NONE;
}

EXT_API_FUN(_confd_set_debug, EXT_API_FUN_LIB_SET_DEBUG)
{
    static char *kwlist[] = { "level", "file", NULL };
    enum confd_debug_level dbglvl = CONFD_DEBUG;
    PyObject *f = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iO", kwlist, &dbglvl, &f)) {
        return NULL;
    }
    if (!set_debug_stream(f)) {
        return NULL;
    }
    if (!f) {
        g_debug_stream = stderr;
    }

    CHECK_CONFD_ERR(confd_set_debug(dbglvl, g_debug_stream));
    Py_RETURN_NONE;
}

static PyObject *_pystring_from_buf(char *buf)
{
    PyObject *str = PyString_FromString(buf);
    free(buf);
    return str;
}

EXT_API_FUN(_confd_pp_kpath, EXT_API_FUN_LIB_PP_KPATH)
{
    static char *kwlist[] = {
        "hkeypath",
        NULL
    };

    confdHKeypathRef *pykpath;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &pykpath)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject *)pykpath)) {
        PyErr_Format(PyExc_TypeError,
                     "hkeypath argument must be a "
                     CONFD_PY_MODULE ".HKeypathRef instance");

         return NULL;
    }

    char *buf = malloc(INITIAL_BUF_SIZE + 1);
    int res = confd_pp_kpath(buf, INITIAL_BUF_SIZE, pykpath->kp);
    if (res >= INITIAL_BUF_SIZE) {
        buf = realloc(buf, res + 2);
        res = confd_pp_kpath(buf, res + 1, pykpath->kp);
    }

    CHECK_CONFD_ERR_EXECERR(res, free(buf));

    return _pystring_from_buf(buf);
}


EXT_API_FUN(_confd_pp_kpath_len, EXT_API_FUN_LIB_PP_KPATH_LEN)
{
    static char *kwlist[] = {
        "hkeypath",
        "len",
        NULL
    };

    confdHKeypathRef *hkp;
    int len;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &hkp, &len)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject*)hkp)) {
        PyErr_Format(PyExc_TypeError,
                     "hkeypath argument must be a "
                     CONFD_PY_MODULE ".HKeypathRef instance");

         return NULL;
    }

    if (hkp->kp == NULL) {
        return PyString_FromString("");
    } else if (len > hkp->kp->len) {
        PyErr_Format(PyExc_ValueError,
                     "len %d greater than hkeypath len %d", len, hkp->kp->len);
         return NULL;
    } else {
        char *buf = malloc(INITIAL_BUF_SIZE + 1);
        int res = confd_pp_kpath_len(buf, INITIAL_BUF_SIZE, hkp->kp, len);
        if (res >= INITIAL_BUF_SIZE) {
            buf = realloc(buf, res + 2);
            res = confd_pp_kpath_len(buf, res + 1, hkp->kp, len);
        }

        CHECK_CONFD_ERR_EXECERR(res, free(buf));

        return _pystring_from_buf(buf);
    }
}

/* ************************************************************************ */
/*  confd_stream_connect                                                    */
/* ************************************************************************ */

EXT_API_FUN(_confd_stream_connect, EXT_API_FUN_LIB_STREAM_CONNECT)
{
    static char *kwlist[] = {
        "sock",
        "id",
        "flags",
        "ip",
        "port",
        "path",
        NULL
    };

    PyObject *sock, *tmp;
    int s, family;
    int id;
    int flags;
    char *ipstr = NULL;
    int port = -1;
    char *pstr = NULL;

    struct in_addr in;
    struct sockaddr_in inaddr;
    struct sockaddr_in6 inaddr6;
    struct sockaddr_un unaddr;
    struct sockaddr *addr;
    socklen_t addrlen;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "Oii|sis", kwlist,
            &sock, &id, &flags, &ipstr, &port, &pstr)) {
        return NULL;
    }

    /* Fish out information from socket object... */
    if ((tmp = PyObject_CallMethod(sock, "fileno", NULL)) == NULL) {
        /* CallMethod sets up the exception */
        return NULL;
    }
    s = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    if ((tmp = PyObject_GetAttrString(sock, "family")) == NULL) {
        return 0;
    }
    family = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    /* should check that type = SOCK_STREAM */

    switch (family) {
    case AF_UNIX: {
        if (!pstr) {
            PyErr_SetString(PyExc_TypeError,
                    "path argument must be provided for an AF_UNIX socket");
            return NULL;
        }
        unaddr.sun_family = AF_UNIX;
        snprintf(unaddr.sun_path, sizeof(unaddr.sun_path), "%s", pstr);
        addr = (struct sockaddr *)&unaddr;
        addrlen = sizeof(unaddr);
    }
        break;
    case AF_INET: {
        if (!ipstr) {
            PyErr_SetString(PyExc_TypeError,
                    "ip argument must be provided for an AF_INET socket");
            return NULL;
        }
        if (port == -1) {
            PyErr_SetString(PyExc_TypeError,
                    "port argument must be provided for an AF_INET socket");
            return NULL;
        }
        if (inet_pton(AF_INET, ipstr, &in) != 1) {
            return
                PyErr_Format(PyExc_ValueError, "invalid IP address: %s", ipstr);
        }
        inaddr.sin_family = AF_INET;
        inaddr.sin_addr.s_addr = in.s_addr;
        inaddr.sin_port = htons(port);
        addr = (struct sockaddr *)&inaddr;
        addrlen = sizeof(inaddr);
    }
        break;

    case AF_INET6 :
        if (!ipstr) {
            PyErr_SetString(PyExc_TypeError,
                    "ip argument must be provided for an AF_INET6 socket");
            return NULL;
        }
        if (port == -1) {
            PyErr_SetString(PyExc_TypeError,
                    "port argument must be provided for an AF_INET6 socket");
            return NULL;
        }
        if (inet_pton(AF_INET6, ipstr, &inaddr6.sin6_addr) != 1) {
            return
                PyErr_Format(PyExc_ValueError, "invalid IPv6 address: %s",
                                ipstr);
        }
        inaddr6.sin6_family = AF_INET6;

        inaddr6.sin6_port = htons(port);
        addr = (struct sockaddr *)&inaddr6;
        addrlen = sizeof(inaddr6);
        break;

    default:
        PyErr_Format(PyExc_TypeError, "unsupported socket family: %d", family);
        return NULL;
    }

    CHECK_CONFD_ERR(confd_stream_connect(s, addr, addrlen, id, flags));

    Py_RETURN_NONE;
}

/* ************************************************************************ */
/*  confd_find_cs_root                                                      */
/* ************************************************************************ */

EXT_API_FUN(_confd_find_cs_root, EXT_API_FUN_LIB_FIND_CS_ROOT)
{
    static char *kwlist[] = {
        "ns",
        NULL
    };

    u_int32_t ns;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "I", kwlist, &ns)) {
        return NULL;
    }

    struct confd_cs_node *node;

    CONFD_EXEC(node = confd_find_cs_root(ns));

    if (node) {
        return newConfdCsNode(node);
    }

    Py_RETURN_NONE;
}

/* ************************************************************************ */
/*  confd_cs_node_cd                                                        */
/* ************************************************************************ */

EXT_API_FUN(_confd_cs_node_cd, EXT_API_FUN_LIB_CS_NODE_CD)
{
    static char *kwlist[] = {
        "start",
        "path",
        NULL
    };

    PyObject *start;
    char *path;
    struct confd_cs_node *cstart = NULL;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "OO&", kwlist, &start, path_arg, &path)) {
        return NULL;
    }

    if (isConfdCsNode(start)) {
        cstart = ((confdCsNode*)start)->node;
    }
    else if (start != Py_None) {
            PyErr_Format(PyExc_TypeError,
                    "start argument must be None or a "
                    CONFD_PY_MODULE ".CsNode instance");
            return NULL;
    }

    struct confd_cs_node *node;

    CONFD_EXEC(node = confd_cs_node_cd(cstart, path));
    free(path);

    if (!node) {
        PyErr_Format(PyExc_ValueError, "Keypath %s not found", path);
        return NULL;
    }

    return newConfdCsNode(node);
}

/* ************************************************************************ */
/*  confd_find_ns_type                                                      */
/* ************************************************************************ */

EXT_API_FUN(_confd_find_ns_type, EXT_API_FUN_LIB_FIND_NS_TYPE)
{
    static char *kwlist[] = {
        "nshash",
        "name",
        NULL
    };

    u_int32_t nshash;
    char *name;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "Is", kwlist, &nshash, &name)) {
        return NULL;
    }

    struct confd_type *type;

    CONFD_EXEC(type = confd_find_ns_type(nshash, name));

    if (type) {
        return newConfdCsType(type);
    }

    Py_RETURN_NONE;
}


/* ************************************************************************ */
/*  confd_ns2prefix                                                         */
/* ************************************************************************ */

EXT_API_FUN(_confd_ns2prefix, EXT_API_FUN_LIB_NS2PREFIX)
{
    static char *kwlist[] = {
        "nshash",
        NULL
    };

    u_int32_t nshash;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "I", kwlist, &nshash)) {
        return NULL;
    }

    char *prefix;

    CONFD_EXEC(prefix = confd_ns2prefix(nshash));

    if (prefix) {
        return PyString_FromString(prefix);
    }

    Py_RETURN_NONE;
}


/* ************************************************************************ */
/*  confd_hash2str                                                          */
/* ************************************************************************ */

EXT_API_FUN(_confd_hash2str, EXT_API_FUN_LIB_HASH2STR)
{
    static char *kwlist[] = {
        "hash",
        NULL
    };

    u_int32_t hash;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "I", kwlist, &hash)) {
        return NULL;
    }

    char *str;

    CONFD_EXEC(str = confd_hash2str(hash));

    if (str) {
        return PyString_FromString(str);
    }

    Py_RETURN_NONE;
}

/* ************************************************************************ */
/*  confd_mmap_schemas                                                      */
/* ************************************************************************ */

EXT_API_FUN(_confd_mmap_schemas, EXT_API_FUN_LIB_MMAP_SCHEMAS)
{
    static char *kwlist[] = {
        "filename",
        NULL
    };

    char *filename;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &filename)) {
        return NULL;
    }

    CHECK_CONFD_ERR(confd_mmap_schemas(filename));
    Py_RETURN_NONE;
}


/* ************************************************************************ */
/*  confd_str2hash                                                          */
/* ************************************************************************ */

EXT_API_FUN(_confd_str2hash, EXT_API_FUN_LIB_STR2HASH)
{
    static char *kwlist[] = {
        "str",
        NULL
    };

    char *str;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &str)) {
        return NULL;
    }

    u_int32_t hash;

    CONFD_EXEC(hash = confd_str2hash(str));

    return PyInt_FromLong(hash);
}


/* ************************************************************************ */
/*  confd_fatal                                                             */
/* ************************************************************************ */

EXT_API_FUN(_confd_fatal, EXT_API_FUN_LIB_FATAL)
{
    static char *kwlist[] = {
        "str",
        NULL
    };

    char *str;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &str)) {
        return NULL;
    }

    CONFD_EXEC(confd_fatal("%s", str));

    Py_RETURN_NONE;
}

/* ************************************************************************ */
/*  confd_decrypt                                                           */
/* ************************************************************************ */

EXT_API_FUN(_confd_decrypt, EXT_API_FUN_LIB_DECRYPT)
{
    static char *kwlist[] = {
        "ciphertext",
        NULL
    };

    char *ciphertext;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &ciphertext)) {
        return NULL;
    }

    size_t len = strlen(ciphertext);
    char buf[len + 1];

    memset(buf, 0, sizeof(buf));

    CHECK_CONFD_ERR(confd_decrypt(ciphertext, len, buf));

    PyObject *ret = PyString_FromString(buf);
    if (ret == NULL) {
        PyErr_Format(PyExc_ValueError,
                     "unable to decrypt string (wrong crypto keys?)");
    }
    return ret;
}

EXT_API_FUN(_confd_find_cs_node, EXT_API_FUN_LIB_FIND_CS_NODE)
{
    static char *kwlist[] = {
        "hkeypath",
        "len",
        NULL
    };

    confdHKeypathRef *hkp;
    int len = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", kwlist,
                &hkp, &len)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject*)hkp)) {
        PyErr_Format(PyExc_TypeError,
                "hkeypath argument must a "
                CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    struct confd_cs_node *node;

    CONFD_EXEC(node = confd_find_cs_node(hkp->kp, len));

    if (node) {
        return newConfdCsNode(node);
    }

    Py_RETURN_NONE;
}

EXT_API_FUN(_confd_find_cs_node_child, EXT_API_FUN_LIB_FIND_CS_NODE_CHILD)
{
    static char *kwlist[] = {
        "parent",
        "xmltag",
        NULL
    };

    confdCsNode *parent;
    PyConfd_XmlTag_Object *xmltag;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &parent, &xmltag)) {
        return NULL;
    }

    if (!isConfdCsNode((PyObject*)parent)) {
        PyErr_Format(PyExc_TypeError,
            "parent argument must be a "
            CONFD_PY_MODULE ".CsNode instance");
    }

    if (!PyConfd_XmlTag_CheckExact((PyObject*)xmltag)) {
        PyErr_Format(PyExc_TypeError,
            "xmltag argument must be a "
            CONFD_PY_MODULE ".XmlTag instance");

        return NULL;
    }

    struct xml_tag cxmltag;
    cxmltag.tag = xmltag->tag;
    cxmltag.ns = xmltag->ns;

    struct confd_cs_node *child;

    CONFD_EXEC(child = confd_find_cs_node_child(parent->node, cxmltag));

    if (child) {
        return newConfdCsNode(child);
    }

    Py_RETURN_NONE;
}


EXT_API_FUN(_confd_hkp_tagmatch, EXT_API_FUN_LIB_HKP_TAGMATCH)
{
    static char *kwlist[] = {
        "hkeypath",
        "tags",
        NULL
    };

    confdHKeypathRef *hkp;
    PyObject *tags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &hkp, &tags)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject*)hkp)) {
        PyErr_Format(PyExc_TypeError,
                "hkeypath argument must a "
                CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    if (!PyList_Check(tags)) {
        PyErr_Format(PyExc_TypeError,
                "tags argument must be a list of "
                CONFD_PY_MODULE ".XmlTag instances");
        return NULL;
    }

    int tagslen = (int)PyList_Size(tags);
    struct xml_tag ctags[tagslen];
    int i;
    PyConfd_XmlTag_Object *o;

    for (i = 0; i < tagslen; i++) {
        o = (PyConfd_XmlTag_Object*)PyList_GetItem(tags, i);
        if (!PyConfd_XmlTag_CheckExact((PyObject*)o)) {
            PyErr_Format(PyExc_TypeError,
                    "item %d in tags argument must be a "
                    CONFD_PY_MODULE ".XmlTag instance", i);
            return NULL;
        }
        ctags[i].tag = o->tag;
        ctags[i].ns = o->ns;
    }

    int ret;
    CONFD_EXEC(ret = confd_hkp_tagmatch(ctags, tagslen, hkp->kp));

    return PyInt_FromLong(ret);
}


EXT_API_FUN(_confd_hkp_prefix_tagmatch, EXT_API_FUN_LIB_HKP_PREFIX_TAGMATCH)
{
    static char *kwlist[] = {
        "hkeypath",
        "tags",
        NULL
    };

    confdHKeypathRef *hkp;
    PyObject *tags;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OO", kwlist,
                &hkp, &tags)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject*)hkp)) {
        PyErr_Format(PyExc_TypeError,
                "hkeypath argument must a "
                CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    if (!PyList_Check(tags)) {
        PyErr_Format(PyExc_TypeError,
                "tags argument must be a list of "
                CONFD_PY_MODULE ".XmlTag instances");
        return NULL;
    }

    int tagslen = (int)PyList_Size(tags);
    struct xml_tag ctags[tagslen];
    int i;
    PyConfd_XmlTag_Object *o;

    for (i = 0; i < tagslen; i++) {
        o = (PyConfd_XmlTag_Object*)PyList_GetItem(tags, i);
        if (!PyConfd_XmlTag_CheckExact((PyObject*)o)) {
            PyErr_Format(PyExc_TypeError,
                    "item %d in tags argument must be a "
                    CONFD_PY_MODULE ".XmlTag instance", i);
            return NULL;
        }
        ctags[i].tag = o->tag;
        ctags[i].ns = o->ns;
    }


    int ret;
    CONFD_EXEC(ret = confd_hkp_prefix_tagmatch(ctags, tagslen, hkp->kp));

    if (ret == 1) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


EXT_API_FUN(_confd_hkeypath_dup, EXT_API_FUN_LIB_HKEYPATH_DUP)
{
    static char *kwlist[] = {
        "hkeypath",
        NULL
    };

    confdHKeypathRef *hkp;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &hkp)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject*)hkp)) {
        PyErr_Format(PyExc_TypeError,
                "hkeypath argument must a "
                CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    confd_hkeypath_t *dup;

    CONFD_EXEC(dup = confd_hkeypath_dup(hkp->kp));

    return newConfdHKeypathRefAutoFree(dup);
}


EXT_API_FUN(_confd_hkeypath_dup_len, EXT_API_FUN_LIB_HKEYPATH_DUP_LEN)
{
    static char *kwlist[] = {
        "hkeypath",
        "len",
        NULL
    };

    confdHKeypathRef *hkp;
    int len;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Oi", kwlist,
                &hkp, &len)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject*)hkp)) {
        PyErr_Format(PyExc_TypeError,
                "hkeypath argument must a "
                CONFD_PY_MODULE ".HKeypathRef instance");
        return NULL;
    }

    confd_hkeypath_t *dup;

    CONFD_EXEC(dup = confd_hkeypath_dup_len(hkp->kp, len));

    return newConfdHKeypathRefAutoFree(dup);
}

EXT_API_FUN(_confd_max_object_size, EXT_API_FUN_LIB_MAX_OBJECT_SIZE)
{
    static char *kwlist[] = {
        "object",
        NULL
    };

    confdCsNode *object;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &object)) {
        return NULL;
    }

    if (!isConfdCsNode((PyObject*)object)) {
        PyErr_Format(PyExc_TypeError,
            "object argument must be a "
            CONFD_PY_MODULE ".CsNode instance");
    }

    int size;
    CHECK_CONFD_ERR(size = confd_max_object_size(object->node));

    return PyInt_FromLong(size);
}

EXT_API_FUN(_confd_next_object_node, EXT_API_FUN_LIB_NEXT_OBJECT_NODE)
{
    static char *kwlist[] = {
        "object",
        "cur",
        "value",
        NULL
    };

    confdCsNode *object;
    confdCsNode *cur;
    PyConfd_Value_Object *value;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "OOO", kwlist,
                &object, &cur, &value)) {
        return NULL;
    }

    if (!isConfdCsNode((PyObject*)object)) {
        PyErr_Format(PyExc_TypeError,
            "object argument must be a "
            CONFD_PY_MODULE ".CsNode instance");

        return NULL;
    }

    if (!isConfdCsNode((PyObject*)cur)) {
        PyErr_Format(PyExc_TypeError,
            "cur argument must be a "
            CONFD_PY_MODULE ".CsNode instance");

        return NULL;
    }

    if (!PyConfd_Value_CheckExact((PyObject*)value)) {
        PyErr_Format(PyExc_TypeError,
            "value argument must be a "
            CONFD_PY_MODULE ".Value instance");

        return NULL;
    }

    struct confd_cs_node *child;

    CONFD_EXEC(child = confd_next_object_node(
                            object->node, cur->node, &value->ob_val));

    if (child) {
        return newConfdCsNode(child);
    }

    Py_RETURN_NONE;
}


EXT_API_FUN(_confd_get_leaf_list_type, EXT_API_FUN_LIB_GET_LEAF_LIST_TYPE)
{
    static char *kwlist[] = {
        "node",
        NULL
    };

    confdCsNode *node;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &node)) {
        return NULL;
    }

    if (!isConfdCsNode((PyObject*)node)) {
        PyErr_Format(PyExc_TypeError,
            "node argument must be a "
            CONFD_PY_MODULE ".CsNode instance");

        return NULL;
    }

    struct confd_type *type;

    CONFD_EXEC(type = confd_get_leaf_list_type(node->node));

    if (!type) {
        PyErr_Format(PyExc_Exception, "schema information not loaded");
        return NULL;
    }

    return newConfdCsType(type);
}

// ----------------------------------------------------------------------------

EXT_API_FUN(_confd_get_nslist, EXT_API_FUN_LIB_GET_NSLIST)
{
    static char *kwlist[] = {
        NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist)) {
        return NULL;
    }

    struct confd_nsinfo *nslist;
    int count, i;

    CHECK_CONFD_ERR(count = confd_get_nslist(&nslist));

    PyObject *l = PyList_New(count);

    for (i = 0; i < count; ++i) {
        PyObject *tup = PyTuple_New(5);
        PyTuple_SetItem(tup, 0, PyInt_FromLong(nslist[i].hash));
        PyTuple_SetItem(tup, 1, PyString_FromString(nslist[i].prefix));
        PyTuple_SetItem(tup, 2, PyString_FromString(nslist[i].uri));
        if (nslist[i].revision)
            PyTuple_SetItem(tup, 3, PyString_FromString(nslist[i].revision));
        else
            PyTuple_SetItem(tup, 3, PyString_FromString(""));
        if (nslist[i].module)
            PyTuple_SetItem(tup, 4, PyString_FromString(nslist[i].module));
        else
            PyTuple_SetItem(tup, 4, PyString_FromString(""));
        PyList_SetItem(l, i, tup);
    }

    return l;
}

EXT_API_FUN(_confd_xpath_pp_kpath, EXT_API_FUN_LIB_XPATH_PP_KPATH)
{
    static char *kwlist[] = {
        "hkeypath",
        NULL
    };

    confdHKeypathRef *pykpath;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &pykpath)) {
        return NULL;
    }

    if (!isConfdHKeypathRef((PyObject *)pykpath)) {
        PyErr_Format(PyExc_TypeError,
                     "hkeypath argument must be a "
                     CONFD_PY_MODULE ".HKeypathRef instance");

         return NULL;
    }

    char *buf = malloc(INITIAL_BUF_SIZE + 1);
    int res = confd_xpath_pp_kpath(buf, INITIAL_BUF_SIZE, 0, pykpath->kp);
    if (res >= INITIAL_BUF_SIZE) {
        buf = realloc(buf, res + 2);
        res = confd_xpath_pp_kpath(buf, res + 1, 0, pykpath->kp);
    }

    CHECK_CONFD_ERR_EXECERR(res, free(buf));

    return _pystring_from_buf(buf);
}

EXT_API_FUN(_confd_list_filter_type2str, EXT_API_FUN_LIB_LIST_FILTER_TYPE2STR)
{
    static char *kwlist[] = {
        "type",
        NULL
    };

    int type;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &type)) {
        return NULL;
    }

    switch (type) {
    case CONFD_LF_OR:
        return PyString_FromString("LF_OR");
    case CONFD_LF_AND:
        return PyString_FromString("LF_AND");
    case CONFD_LF_NOT:
        return PyString_FromString("LF_NOT");
    case CONFD_LF_CMP:
        return PyString_FromString("LF_CMP");
    case CONFD_LF_EXISTS:
        return PyString_FromString("LF_EXISTS");
    case CONFD_LF_EXEC:
        return PyString_FromString("LF_EXEC");
    case CONFD_LF_ORIGIN:
        return PyString_FromString("LF_ORIGIN");
    default:
        PyErr_Format(PyExc_ValueError, "invalid type");
        return NULL;
    }
}

EXT_API_FUN(_confd_expr_op2str, EXT_API_FUN_LIB_EXPR_OP2STR)
{
    static char *kwlist[] = {
        "op",
        NULL
    };

    int op;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &op)) {
        return NULL;
    }

    switch (op) {
    case CONFD_CMP_NOP:
        return PyString_FromString("CMP_NOP");
    case CONFD_CMP_EQ:
        return PyString_FromString("CMP_EQ");
    case CONFD_CMP_NEQ:
        return PyString_FromString("CMP_NEQ");
    case CONFD_CMP_GT:
        return PyString_FromString("CMP_GT");
    case CONFD_CMP_GTE:
        return PyString_FromString("CMP_GTE");
    case CONFD_CMP_LT:
        return PyString_FromString("CMP_LT");
    case CONFD_CMP_LTE:
        return PyString_FromString("CMP_LTE");
    case CONFD_EXEC_STARTS_WITH:
        return PyString_FromString("EXEC_STARTS_WITH");
    case CONFD_EXEC_RE_MATCH:
        return PyString_FromString("EXEC_RE_MATCH");
    case CONFD_EXEC_DERIVED_FROM:
        return PyString_FromString("EXEC_DERIVED_FROM");
    case CONFD_EXEC_DERIVED_FROM_OR_SELF:
        return PyString_FromString("EXEC_DERIVED_FROM_OR_SELF");
    default:
        PyErr_Format(PyExc_ValueError, "invalid op");
        return NULL;
    }
}

#if CONFD_PY_PRODUCT_NCS

/* set_kill_child_on_parent_exit function currently only used from
   NCS */
EXT_API_FUN(_confd_set_kill_child_on_parent_exit,
            EXT_API_FUN_LIB_SET_KILL_CHILD_ON_PARENT_EXIT)
{
    static char *kwlist[] = { NULL };
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist)) {
        return NULL;
    }

#ifdef HAVE_SYS_PRCTL_H
    int err = prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0, 0);
    if (err == 0) {
        Py_RETURN_TRUE;
    }
#endif /* HAVE_SYS_ PRCTL_H */
    Py_RETURN_FALSE;
}

/* Internal connect function currently only used from NCS PyVM */
EXT_API_FUN(_confd_internal_connect, EXT_API_FUN_LIB_INTERNAL_CONNECT)
{
    static char *kwlist[] = { "id", "sock", "ip", "port", "path", NULL };

    PyObject *sock, *tmp;
    int id;
    int s, family;
    char *ipstr = NULL;
    int port;
    char *pstr = NULL;

    struct in_addr in;
    struct sockaddr_in inaddr;
    struct sockaddr_in6 inaddr6;
    struct sockaddr_un unaddr;
    struct sockaddr *addr;
    socklen_t addrlen;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwds, "iO|sis", kwlist, &id, &sock, &ipstr, &port, &pstr)) {
        return NULL;
    }

    /* Fish out information from socket object... */
    if ((tmp = PyObject_CallMethod(sock, "fileno", NULL)) == NULL) {
        /* CallMethod sets up the exception */
        return NULL;
    }
    s = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    if ((tmp = PyObject_GetAttrString(sock, "family")) == NULL) {
        return 0;
    }
    family = (int)PyInt_AsLong(tmp);
    Py_DECREF(tmp);
    /* should check that type = SOCK_STREAM */

    switch (family) {
    case AF_UNIX:
        if (!pstr) {
            PyErr_SetString(PyExc_TypeError,
                    "path argument must be provided for an AF_UNIX socket");
            return NULL;
        }
        unaddr.sun_family = AF_UNIX;
        snprintf(unaddr.sun_path, sizeof(unaddr.sun_path), "%s", pstr);
        addr = (struct sockaddr *)&unaddr;
        addrlen = sizeof(unaddr);
        break;

    case AF_INET:
        if (!ipstr) {
            PyErr_SetString(PyExc_TypeError,
                    "ip argument must be provided for an AF_INET socket");
            return NULL;
        }
        if (port == -1) {
            PyErr_SetString(PyExc_TypeError,
                    "port argument must be provided for an AF_INET socket");
            return NULL;
        }
        if (inet_pton(AF_INET, ipstr, &in) != 1) {
            return
                PyErr_Format(PyExc_ValueError, "invalid IP address: %s", ipstr);
        }
        inaddr.sin_family = AF_INET;
        inaddr.sin_addr.s_addr = in.s_addr;

        inaddr.sin_port = htons(port);
        addr = (struct sockaddr *)&inaddr;
        addrlen = sizeof(inaddr);
        break;

    case AF_INET6 :
        if (!ipstr) {
            PyErr_SetString(PyExc_TypeError,
                    "ip argument must be provided for an AF_INET6 socket");
            return NULL;
        }
        if (port == -1) {
            PyErr_SetString(PyExc_TypeError,
                    "port argument must be provided for an AF_INET6 socket");
            return NULL;
        }
        if (inet_pton(AF_INET6, ipstr, &inaddr6.sin6_addr) != 1) {
            return
                PyErr_Format(PyExc_ValueError, "invalid IPv6 address: %s",
                             ipstr);
        }
        inaddr6.sin6_family = AF_INET6;

        inaddr6.sin6_port = htons(port);
        addr = (struct sockaddr *)&inaddr6;
        addrlen = sizeof(inaddr6);
        break;

    default:
        PyErr_Format(PyExc_TypeError, "unsupported socket family: %d", family);
        return NULL;
    }

    CHECK_CONFD_ERR(confd_do_connect(s, addr, addrlen, id));

    Py_RETURN_NONE;
}
#endif /* CONFD_PY_PRODUCT_NCS */

#ifdef CONFD_PY_EXT_API_TIMING

EXT_API_FUN(_confd_ext_api_timing, EXT_API_FUN_LIB_EXT_API_TIMING)
{
    PyObject *res = PyDict_New();
    for (int i = 0; EXT_API_FUN_ID_TO_STR[i] != NULL; i++) {
        PyObject *stats = PyDict_New();
        PYDICT_SET_ITEM(stats, "count", PyInt_FromLong(EXT_API_COUNT[i]));
        double elapsed_ms = ((double) EXT_API_TIME[i]) / 1000000;
        PYDICT_SET_ITEM(stats, "elapsed_ms", PyFloat_FromDouble(elapsed_ms));
        double call_ms = ((double) EXT_API_TIME_IN_CALL[i]) / 1000000;
        PYDICT_SET_ITEM(stats, "call_ms", PyFloat_FromDouble(call_ms));
        PYDICT_SET_ITEM(res, EXT_API_FUN_ID_TO_STR[i], stats);
    }
    return res;
}

#endif /* CONFD_PY_EXT_API_TIMING */


/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#include "../doc/src/lib_doc.c"

#define PYMOD_ENTRY(NAME) {# NAME, (PyCFunction)_confd_ ## NAME, \
                           METH_VARARGS | METH_KEYWORDS, \
                           _confd_ ## NAME ## __doc__}


static PyMethodDef confd_lib_Methods[] = {
    PYMOD_ENTRY(init),
    PYMOD_ENTRY(set_debug),
    PYMOD_ENTRY(pp_kpath),
    PYMOD_ENTRY(pp_kpath_len),
    PYMOD_ENTRY(stream_connect),
    PYMOD_ENTRY(find_cs_root),
    PYMOD_ENTRY(cs_node_cd),
    PYMOD_ENTRY(find_ns_type),
    PYMOD_ENTRY(ns2prefix),
    PYMOD_ENTRY(hash2str),
    PYMOD_ENTRY(str2hash),
    PYMOD_ENTRY(mmap_schemas),
    PYMOD_ENTRY(fatal),
    PYMOD_ENTRY(decrypt),
    PYMOD_ENTRY(find_cs_node),
    PYMOD_ENTRY(find_cs_node_child),
    PYMOD_ENTRY(hkp_tagmatch),
    PYMOD_ENTRY(hkp_prefix_tagmatch),
    PYMOD_ENTRY(hkeypath_dup),
    PYMOD_ENTRY(hkeypath_dup_len),
    PYMOD_ENTRY(max_object_size),
    PYMOD_ENTRY(next_object_node),
    PYMOD_ENTRY(get_leaf_list_type),
    PYMOD_ENTRY(get_nslist),
    PYMOD_ENTRY(xpath_pp_kpath),
    PYMOD_ENTRY(list_filter_type2str),
    PYMOD_ENTRY(expr_op2str),
#if CONFD_PY_PRODUCT_NCS
    PYMOD_ENTRY(set_kill_child_on_parent_exit),
    PYMOD_ENTRY(internal_connect),
#endif
#ifdef CONFD_PY_EXT_API_TIMING
    PYMOD_ENTRY(ext_api_timing),
#endif /* CONFD_PY_EXT_API_TIMING */

    {NULL, NULL, 0, NULL}
};

#undef PYMOD_ENTRY


/* ************************************************************************ */
/* Module initialization                                                    */
/* ************************************************************************ */

#define MODULE CONFD_PY_MODULE ".lib"

static struct PyModuleDef moduledef = {
        PyModuleDef_HEAD_INIT,
        MODULE,
        LIB_MODULE_DOCSTR(CONFD_PY_PRODUCT)
#if CONFD_PY_PRODUCT_NCS
        LIB_MODULE_DOCSTR_NCS
#endif
        ,
        0,
        confd_lib_Methods,
        NULL,
        NULL,
        NULL,
        NULL
};

PyObject* init__lib_module(void)
{
    PyObject *m = NULL;

    if ((m = PyModule_Create(&moduledef)) == NULL) {
        goto error;
    }

    init_lib_types(m);

    /* Add constants */
#define ADD_CONST(C_NAME, PY_NAME) \
    (void)PyModule_AddIntConstant(m, PY_NAME, C_NAME);

#define ADD_CONST_STR(C_NAME, PY_NAME) \
    (void)PyModule_AddStringConstant(m, PY_NAME, C_NAME);

/* PORT constant is different depending on module */
#ifdef CONFD_PY_PRODUCT_NCS
    ADD_CONST(NCS_PORT, "PORT");
#else
    ADD_CONST(CONFD_PORT, "PORT");
#endif

    ADD_CONST(CONFD_PORT, "CONFD_PORT");
    ADD_CONST(NCS_PORT, "NCS_PORT");

    ADD_CONST(CONFD_OK, "CONFD_OK");
    ADD_CONST(CONFD_ERR, "CONFD_ERR");
    ADD_CONST(CONFD_EOF, "CONFD_EOF");

#include "gen_add_lib_const.c"

#undef ADD_CONST
#undef ADD_CONST_STR

error:
    if (PyErr_Occurred()) {
        PyErr_SetString(PyExc_ImportError, MODULE " : init failed");
        return NULL;
    } else {
        return m;
    }
}
