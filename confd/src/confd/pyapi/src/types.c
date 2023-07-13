/*
 * Copyright 2013 Tail-F Systems AB
 */

// include first, order is significant to get defines correct
#include "confdpy_config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <confd.h>

#include "types.h"
#include "types_iter.h"

#include <structmember.h>
#include "confdpy_err.h"
#include "common.h"

#include "../doc/src/types_doc.c"

#define INITIAL_BUF_SIZE 1024

/* Add a Python object to a Dict.
   This function does the same thing as PyDict_SetItemString() but DECREF's
   obj before returning, effectively stealing a reference to obj. */
void PYDICT_SET_ITEM(PyObject *d, const char *name, PyObject *obj)
{
    assert(obj != Py_None);
    PyDict_SetItemString(d, name, obj);
    Py_DECREF(obj);
}

#define MTH_DEF(prefix, name, flags) \
    {#name, (PyCFunction)prefix ## _ ## name, flags, \
        prefix ## _ ## name ## __doc__}

static PyTypeObject *confdValueType = NULL;
static PyTypeObject *confdTagValueType = NULL;
static PyTypeObject *confdAttrValueType = NULL;
static PyTypeObject *confdXmlTagType = NULL;
static PyTypeObject *confdHKeypathRefType = NULL;
static PyTypeObject *confdTransCtxRefType = NULL;
static PyTypeObject *confdDbCtxRefType = NULL;
static PyTypeObject *confdUserInfoType = NULL;
static PyTypeObject *confdAuthorizationInfoType = NULL;
static PyTypeObject *confdAuthCtxRefType = NULL;
static PyTypeObject *confdAuthorizationCtxRefType = NULL;
static PyTypeObject *confdNotificationCtxRefType = NULL;
static PyTypeObject *confdNotificationsDataType = NULL;
static PyTypeObject *confdNotificationType = NULL;
static PyTypeObject *confdDateTimeType = NULL;
static PyTypeObject *confdSnmpVarbindType = NULL;
static PyTypeObject *confdDaemonCtxRefType = NULL;
static PyTypeObject *confdMaapiRollbackType = NULL;
static PyTypeObject *confdQueryResultType = NULL;
static PyTypeObject *confdCsNodeType = NULL;
static PyTypeObject *confdCsNodeInfoType = NULL;
static PyTypeObject *confdCsTypeType = NULL;
static PyTypeObject *confdCsChoiceType = NULL;
static PyTypeObject *confdCsCaseType = NULL;
static PyTypeObject *confdTrItemRefType = NULL;
static PyTypeObject *confdListFilterType = NULL;


/* ************************************************************************ */
/* confd_value_t -> confd.Value utility functions                           */
/* ************************************************************************ */

static char *_confd_value_str(confd_value_t *val)
{
    int len = confd_pp_value(NULL, 0, val);
    char *str = (char *)malloc(len+1);
    confd_pp_value(str, len+1, val);
    return str;
}

char *_confd_hkeypath2str(const confd_hkeypath_t *hkeypath, int kp_len)
{
    int len = hkeypath2str(NULL, 0, hkeypath, kp_len);
    char *str = (char *)malloc(len + 2);
    hkeypath2str(str, len + 1, hkeypath, kp_len);
    return str;
}

PyObject *_confd_hkeypath2PyString(const confd_hkeypath_t *hkeypath, int kp_len)
{
    char *str = _confd_hkeypath2str(hkeypath, kp_len);
    PyObject *py_str = PyString_FromString(str);
    free(str);
    return py_str;
}

PyObject *confdValue_str(PyConfd_Value_Object *self)
{
    char *str = _confd_value_str(&self->ob_val);
    if (str) {
        PyObject *ret = PyString_FromString(str);
        free(str);
        return ret;
     } else {
        Py_RETURN_NONE;
    }
}


static const char *type2str(enum confd_vtype type)
{
    switch (type) {
    case C_NOEXISTS: return "C_NOEXISTS";
    case C_XMLTAG: return "C_XMLTAG";
    case C_SYMBOL: return "C_SYMBOL";
    case C_STR: return "C_STR";
    case C_BUF: return "C_BUF";
    case C_INT8: return "C_INT8";
    case C_INT16: return "C_INT16";
    case C_INT32: return "C_INT32";
    case C_INT64: return "C_INT64";
    case C_UINT8: return "C_UINT8";
    case C_UINT16: return "C_UINT16";
    case C_UINT32: return "C_UINT32";
    case C_UINT64: return "C_UINT64";
    case C_DOUBLE: return "C_DOUBLE";
    case C_IPV4: return "C_IPV4";
    case C_IPV6: return "C_IPV6";
    case C_BOOL: return "C_BOOL";
    case C_QNAME: return "C_QNAME";
    case C_DATETIME: return "C_DATETIME";
    case C_DATE: return "C_DATE";
    case C_TIME: return "C_TIME";
    case C_DURATION: return "C_DURATION";
    case C_ENUM_HASH: return "C_ENUM_HASH";
    case C_BIT32: return "C_BIT32";
    case C_BIT64: return "C_BIT64";
    case C_BITBIG: return "C_BITBIG";
    case C_LIST: return "C_LIST";
    case C_XMLBEGIN: return "C_XMLBEGIN";
    case C_XMLEND: return "C_XMLEND";
    case C_OBJECTREF: return "C_OBJECTREF";
    case C_UNION: return "C_UNION";
    case C_PTR: return "C_PTR";
    case C_CDBBEGIN: return "C_CDBBEGIN";
    case C_OID: return "C_OID";
    case C_BINARY: return "C_BINARY";
    case C_IPV4PREFIX: return "C_IPV4PREFIX";
    case C_IPV6PREFIX: return "C_IPV6PREFIX";
    case C_IPV4_AND_PLEN: return "C_IPV4_AND_PLEN";
    case C_IPV6_AND_PLEN: return "C_IPV6_AND_PLEN";
    case C_DEFAULT: return "C_DEFAULT";
    case C_DECIMAL64   : return "C_DECIMAL64";
    case C_IDENTITYREF : return "C_IDENTITYREF";
    case C_XMLBEGINDEL : return "C_XMLBEGINDEL";
    case C_DQUAD : return "C_DQUAD";
    case C_HEXSTR : return "C_HEXSTR";
    case C_XMLMOVEFIRST: return "C_XMLMOVEFIRST";
    case C_XMLMOVEAFTER: return "C_XMLMOVEAFTER";

    default: return "UNKNOWN_TYPE";
    }
}

static PyObject *confdValue_repr(PyConfd_Value_Object *self)
{
    int len;
    char vtmpbuf[16];
    vtmpbuf[0] = '\0';
    len = confd_pp_value(vtmpbuf, sizeof(vtmpbuf), &(self->ob_val));
    return PyString_FromFormat("<" CONFD_PY_MODULE
                               ".Value type=%s(%d) value='%s'%s>",
                               type2str(self->ob_val.type), self->ob_val.type,
                               vtmpbuf,
                               (len > (int)sizeof(vtmpbuf)) ? "..." : "");
}

static long duration2long(confd_value_t *vp)
{
    struct confd_duration *d = &(vp->val.duration);

    /* This is the only reasonable interpretation */
    if ((d->months == 0) && (d->years == 0)) {
        /* return the number of seconds */
        return ((long)d->secs) +
            ((long)d->mins  * 60l) +
            ((long)d->hours * 60l * 60l) +
            ((long)d->days  * 60l * 60l * 24l);
    }
    if ((d->secs == 0) && (d->mins == 0) && (d->hours == 0) && (d->days == 0)) {
        /* return the number of months */
        return (long)d->months + (12l * (long)d->years);
    }
    /* They'll have to parse it themselves */
    return 0l;
}

static PyObject *confdValue_as_int(PyConfd_Value_Object *self)
{
    confd_value_t *vp = &self->ob_val;
    switch (self->ob_val.type) {
    case C_INT8:  return PyInt_FromLong((long)CONFD_GET_INT8(vp));
    case C_INT16: return PyInt_FromLong((long)CONFD_GET_INT16(vp));
    case C_INT32: return PyInt_FromLong((long)CONFD_GET_INT32(vp));
    case C_INT64: return PyLong_FromLongLong(CONFD_GET_INT64(vp));
    case C_UINT8:  return PyInt_FromLong((long)CONFD_GET_UINT8(vp));
    case C_UINT16: return PyInt_FromLong((long)CONFD_GET_UINT16(vp));
    case C_UINT32: return PyLong_FromUnsignedLong(CONFD_GET_UINT32(vp));
    case C_UINT64: return PyLong_FromUnsignedLongLong(CONFD_GET_UINT64(vp));
    case C_DOUBLE: return PyLong_FromDouble(CONFD_GET_DOUBLE(vp));
    case C_DURATION: return PyLong_FromDouble(duration2long(vp));
    case C_BOOL: return PyInt_FromLong((long)CONFD_GET_BOOL(vp));
    case C_BIT32:
        return PyLong_FromUnsignedLong((u_int32_t) CONFD_GET_BIT32(vp));
    case C_BIT64: return PyLong_FromUnsignedLongLong(CONFD_GET_BIT64(vp));

#if 0
    case C_IPV4: goto nyitype; break;
    case C_IPV6: goto nyitype; break;
#endif

    case C_ENUM_HASH:
        return PyInt_FromLong((int32_t)CONFD_GET_ENUM_VALUE(vp));

    default:
        PyErr_Format(PyExc_TypeError,
                     "a confd.Value of type %s can not be represented as a "
                     "<type 'int'>", type2str(self->ob_val.type));
        return NULL;
    }
}

static PyObject *confdValue_as_long(PyConfd_Value_Object *self)
{
    confd_value_t *vp = &self->ob_val;
    switch (self->ob_val.type) {
    case C_INT8:  return PyLong_FromLong((long)CONFD_GET_INT8(vp));
    case C_INT16: return PyLong_FromLong((long)CONFD_GET_INT16(vp));
    case C_INT32: return PyLong_FromLong((long)CONFD_GET_INT32(vp));
    case C_INT64: return PyLong_FromLongLong(CONFD_GET_INT64(vp));
    case C_UINT8:  return PyLong_FromUnsignedLong(CONFD_GET_UINT8(vp));
    case C_UINT16: return PyLong_FromUnsignedLong(CONFD_GET_UINT16(vp));
    case C_UINT32: return PyLong_FromUnsignedLong(CONFD_GET_UINT32(vp));
    case C_UINT64: return PyLong_FromUnsignedLongLong(CONFD_GET_UINT64(vp));
    case C_DOUBLE: return PyLong_FromDouble(CONFD_GET_DOUBLE(vp));
    case C_DURATION: return PyLong_FromDouble(duration2long(vp));
    case C_BOOL: return PyLong_FromLong((long)CONFD_GET_BOOL(vp));
    case C_BIT32: return PyLong_FromUnsignedLong(CONFD_GET_BIT32(vp));
    case C_BIT64: return PyLong_FromUnsignedLongLong(CONFD_GET_BIT64(vp));
#if 0
    case C_IPV4: goto nyitype; break;
    case C_IPV6: goto nyitype; break;
#endif

    case C_ENUM_HASH:
        return PyLong_FromLong((int32_t)CONFD_GET_ENUM_VALUE(vp));

    default:
        PyErr_Format(PyExc_TypeError,
                     "a confd.Value of type %s can not be represented as a "
                     "<type 'long'>", type2str(self->ob_val.type));
        return NULL;
    }
}

static PyObject *confdValue_as_float(PyConfd_Value_Object *self)
{
    confd_value_t *vp = &self->ob_val;
    switch (self->ob_val.type) {
    case C_INT8:  return PyFloat_FromDouble((long)CONFD_GET_INT8(vp));
    case C_INT16: return PyFloat_FromDouble((long)CONFD_GET_INT16(vp));
    case C_INT32: return PyFloat_FromDouble((long)CONFD_GET_INT32(vp));
    case C_INT64: return PyFloat_FromDouble(CONFD_GET_INT64(vp));
    case C_UINT8:  return PyFloat_FromDouble(CONFD_GET_UINT8(vp));
    case C_UINT16: return PyFloat_FromDouble(CONFD_GET_UINT16(vp));
    case C_UINT32: return PyFloat_FromDouble(CONFD_GET_UINT32(vp));
    case C_UINT64: return PyFloat_FromDouble(CONFD_GET_UINT64(vp));
    case C_DOUBLE: return PyFloat_FromDouble(CONFD_GET_DOUBLE(vp));
    case C_DURATION: return PyFloat_FromDouble(duration2long(vp));
    case C_BOOL: return PyFloat_FromDouble((long)CONFD_GET_BOOL(vp));
    case C_BIT32: return PyFloat_FromDouble(CONFD_GET_BIT32(vp));
    case C_BIT64: return PyFloat_FromDouble(CONFD_GET_BIT64(vp));
#if 0
    case C_IPV4: goto nyitype; break;
    case C_IPV6: goto nyitype; break;
#endif

    case C_ENUM_HASH :
         return PyFloat_FromDouble((int32_t) CONFD_GET_ENUM_VALUE(vp));

    default:
        PyErr_Format(PyExc_TypeError,
                     "a confd.Value of type %s can not be represented as a "
                     "<type 'float'>", type2str(self->ob_val.type));
        return NULL;
    }
}


static int confdValue_nonzero(PyConfd_Value_Object *self)
{
    confd_value_t *vp = &self->ob_val;

    switch (self->ob_val.type) {
    case C_INT8:
        if (CONFD_GET_INT8(vp) == 0) return 0;
        break;
    case C_INT16:
        if (CONFD_GET_INT16(vp) == 0) return 0;
        break;
    case C_INT32:
        if (CONFD_GET_INT32(vp) == 0) return 0;
        break;
    case C_INT64:
        if (CONFD_GET_INT64(vp) == 0) return 0;
        break;
    case C_UINT8:
        if (CONFD_GET_UINT8(vp) == 0) return 0;
        break;
    case C_UINT16:
        if (CONFD_GET_UINT16(vp) == 0) return 0;
        break;
    case C_UINT32:
        if (CONFD_GET_UINT32(vp) == 0) return 0;
        break;
    case C_UINT64:
        if (CONFD_GET_UINT64(vp) == 0) return 0;
        break;
    case C_DURATION:
        if (duration2long(vp) == 0) return 0;
        break;
    case C_BOOL:
        if (CONFD_GET_BOOL(vp) == 0) return 0;
        break;
    default:
        break;
    }

    return 1;
}


static PyObject *confdValue_richcompare(PyObject *a, PyObject *b, int op)
{
    PyObject *res = NULL;
    int cmp = 0;

    if (!PyConfd_Value_CheckExact(a) || !PyConfd_Value_CheckExact(b)) {
        /* I want to be able to compare against PyInt and PyString as well */
        if (PyConfd_Value_CheckExact(a) && PyInt_Check(b)) {
            PyObject *num = confdValue_as_int((PyConfd_Value_Object *)a);
            if (!num) return NULL;
            res = PyObject_RichCompare(num, b, op);
            Py_DECREF(num);
        } else if (PyConfd_Value_CheckExact(a) && PyLong_Check(b)) {
            PyObject *num = confdValue_as_long((PyConfd_Value_Object *)a);
            res = PyObject_RichCompare(num, b, op);
            Py_DECREF(num);
        } else if (PyConfd_Value_CheckExact(a) && PyString_Check(b)) {
            PyObject *str = confdValue_str((PyConfd_Value_Object *)a);
            res = PyObject_RichCompare(str, b, op);
            Py_DECREF(str);
        } else {
            res = Py_NotImplemented;
        }
    } else {
        /* Now we know we have confdValues */
        PyConfd_Value_Object *av = (PyConfd_Value_Object *)a;
        PyConfd_Value_Object *bv = (PyConfd_Value_Object *)b;
        int iseq = confd_val_eq(&(av->ob_val), &(bv->ob_val));
        /* This sucks, we should implement confd_val_cmp() */
        switch (op) {
        case Py_LT:
        case Py_GT:
            res = Py_NotImplemented;
            break;
        case Py_LE:
        case Py_EQ:
        case Py_GE:
            if (iseq) {
                res = Py_True;
            } else {
                if ((op == Py_LE) || (op == Py_GE)) {
                    res = Py_NotImplemented;
                } else {
                    res = Py_False;
                }
            }
            break;
        case Py_NE:
            if (iseq) {
                res = Py_False;
            } else {
                res = Py_True;
            }
            break;
        }
    }
    if (!res) {
        /* Whenever I implement, set cmp above and use this */
        int istrue = 0;
        switch (op) {
        case Py_EQ: istrue = (cmp == 0); break;
        case Py_NE: istrue = (cmp != 0); break;
        case Py_LE: istrue = (cmp <= 0); break;
        case Py_GE: istrue = (cmp >= 0); break;
        case Py_LT: istrue = (cmp < 0);  break;
        case Py_GT: istrue = (cmp > 0);  break;
        }
        res = istrue ? Py_True : Py_False;
    }
    if (res) { Py_INCREF(res); }
    return res;
}

static void confdValue_dealloc(PyConfd_Value_Object *self)
{
    /* Free confd_value_t types that needs freeing */
    confd_free_dup_to_value(&self->ob_val);

    PY_TP_FREE(self);
}

static int decimal64_init_str(const char *str, struct confd_decimal64 *v)
{
    /* decimal64 representation (RFC 6020)
     *
     +----------------+-----------------------+----------------------+
     | fraction-digit | min                   | max                  |
     +----------------+-----------------------+----------------------+
     | 1              | -922337203685477580.8 | 922337203685477580.7 |
     | 2              | -92233720368547758.08 | 92233720368547758.07 |
     | 3              | -9223372036854775.808 | 9223372036854775.807 |
     | 4              | -922337203685477.5808 | 922337203685477.5807 |
     | 5              | -92233720368547.75808 | 92233720368547.75807 |
     | 6              | -9223372036854.775808 | 9223372036854.775807 |
     | 7              | -922337203685.4775808 | 922337203685.4775807 |
     | 8              | -92233720368.54775808 | 92233720368.54775807 |
     | 9              | -9223372036.854775808 | 9223372036.854775807 |
     | 10             | -922337203.6854775808 | 922337203.6854775807 |
     | 11             | -92233720.36854775808 | 92233720.36854775807 |
     | 12             | -9223372.036854775808 | 9223372.036854775807 |
     | 13             | -922337.2036854775808 | 922337.2036854775807 |
     | 14             | -92233.72036854775808 | 92233.72036854775807 |
     | 15             | -9223.372036854775808 | 9223.372036854775807 |
     | 16             | -922.3372036854775808 | 922.3372036854775807 |
     | 17             | -92.23372036854775808 | 92.23372036854775807 |
     | 18             | -9.223372036854775808 | 9.223372036854775807 |
     +----------------+-----------------------+----------------------+
    */

    size_t slen = strlen(str);
    // the shortest possible number we support is '.x'
    if (slen < 2 || slen > 21)
        return -1;

    const char *p = str;
    char *ctx = NULL;
    char norm[32];
    int ni = 0;

    if (*p == '-') {
        norm[ni++] = '-';
        p++;
    }
    if (*p == '.') {
        norm[ni++] = '0';
    }

    memcpy(&norm[ni], p, slen + 1);

    char *integral = strtok_r(norm, ".", &ctx);
    if (!integral)
        return -1;

    char *fractional = strtok_r(NULL, ".", &ctx);
    if (!fractional)
        return -1;

    char tot[32];
    snprintf(tot, sizeof(tot), "%s%s", integral, fractional);

    v->value = (int64_t)atoll(tot);
    v->fraction_digits = (int)strlen(fractional);

    return 0;
}

static int dquad_from_tuple(PyObject *tup, struct confd_dotted_quad *dquad)
{
    int i, c;
    PyObject *o;

    if (PyTuple_Size(tup) != 4) {
        PyErr_Format(PyExc_ValueError,
                "value must be a 4-tuple of int (0-255)");
        return -1;
    }
    for (i = 0; i < 4; ++i) {
        o = PyTuple_GetItem(tup, i);
        if (!PyNumber_Check(o)) {
            PyErr_Format(PyExc_ValueError,
                    "value must be a 4-tuple of int (0-255)");
            return -1;
        }
        c = (int)PyInt_AsLong(o);
        if (c < 0 || c > 255) {
            PyErr_Format(PyExc_ValueError,
                    "value must be a 4-tuple of int (0-255)");
            return -1;
        }
        dquad->quad[i] = (unsigned char)c;
    }
    return 0;
}

static int dquad_from_string(PyObject *str, struct confd_dotted_quad *dquad)
{
    int ret, t0, t1, t2, t3;

    CONFD_PY_WITH_C_STR(str, s) {
        ret = sscanf(s, "%d.%d.%d.%d", &t0, &t1, &t2, &t3);
    }

    if (ret != 4) {
        PyErr_Format(PyExc_ValueError,
                "value must be a string of type 'aaa.bbb.ccc.ddd'");
        return -1;
    }

    if (t0 < 0 || t0 > 255 || t1 < 0 || t1 > 255 ||
            t2 < 0 || t2 > 255 || t3 < 0 || t3 > 255) {
        PyErr_Format(PyExc_ValueError,
                "dot-values of string must be an int (0-255)");
        return -1;
    }

    dquad->quad[0] = (unsigned char)t0;
    dquad->quad[1] = (unsigned char)t1;
    dquad->quad[2] = (unsigned char)t2;
    dquad->quad[3] = (unsigned char)t3;
    return 0;
}

static void _confd_value_set_buf(confd_value_t *value, enum confd_vtype type,
                                 char *buf, Py_ssize_t sz)
{
    if (type == C_STR) {
        value->val.s = strdup(buf);
    } else {
        value->val.buf.ptr = (unsigned char*)malloc(sz);
        value->val.buf.size = sz;
        memcpy(value->val.buf.ptr, buf, sz);
    }
}

static void _confd_value_set_str(confd_value_t *value, enum confd_vtype type,
                                 PyObject *obj)
{
    char *c_str;
    Py_ssize_t sz;
    PyObject *str = PyObject_Str(obj);
    PyObject *bytes = PyUnicode_AsUTF8String(str);
    /* From the documenation of PyBytes_AsStringAndSize:
       Changed in version 3.5: Previously, TypeError was raised
       when embedded null bytes were encountered in the bytes
       object. */
    sz = PyBytes_Size(bytes);
    c_str = PyBytes_AsString(bytes);
    _confd_value_set_buf(value, type, c_str, sz);
    Py_XDECREF(bytes);
    Py_XDECREF(str);
}

static int _confd_is_int_or_long(PyObject *obj)
{
    return PyInt_Check(obj);
}

static int confdValue_init(PyConfd_Value_Object *self, PyObject *args,
                PyObject *kwds)
{
    int ret;
    PyObject *init = NULL;
    enum confd_vtype type = 0;
    static char *ks[] = { "init", "type", NULL };
    confd_value_t *vp = PyConfd_Value_PTR(self);
    PyObject *tmp = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", ks, &init, &type)) {
        return -1;
    }

    if (type == 0) {
        /* try to deduce type from init value */
        if (PyBool_Check(init)) { type = C_BOOL; }
        else if (PyInt_Check(init)) { type = C_INT32; }
        else if (PyLong_Check(init)) { type = C_INT64; }
        else if (PyFloat_Check(init)) { type = C_DOUBLE; }
        else if (PyString_Check(init)) { type = C_BUF; }
        else if (PyBytes_Check(init)) { type = C_BINARY; }

        /* Anything else will be its string representation stored in a c_buf */
        else { type = C_BUF; }
    }
    switch (type) {
    case C_NOEXISTS:
        CONFD_SET_NOEXISTS(vp);
        break;

    /* init must be a two tuple: (tag, ns) */
    case C_XMLTAG:
    case C_XMLBEGIN:
    case C_XMLBEGINDEL:
    case C_XMLEND:
    case C_XMLMOVEFIRST:
    case C_XMLMOVEAFTER:
        if (!PyTuple_Check(init)) goto badinit;
        if ((PyTuple_Size(init) != 2)) goto badinit;
        if (!PyNumber_Check(PyTuple_GetItem(init, 0))) goto badinit;
        if (!PyNumber_Check(PyTuple_GetItem(init, 1))) goto badinit;
        CONFD_SET_XMLTAG(
                vp,
                (u_int32_t)PyLong_AsLong(PyTuple_GetItem(init, 0)),
                (u_int32_t)PyLong_AsLong(PyTuple_GetItem(init, 1)));
        break;

    case C_SYMBOL:
        goto nyitype;
    case C_STR:
    case C_HEXSTR:
        _confd_value_set_str(&self->ob_val, type, init);
        break;
    case C_BUF:
        if (PyBytes_Check(init)) {
            char *c_str = PyBytes_AsString(init);
            Py_ssize_t sz = PyBytes_Size(init);
            _confd_value_set_buf(&self->ob_val, type, c_str, sz);
        } else {
            _confd_value_set_str(&self->ob_val, type, init);
        }
        break;
    case C_INT8:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Int(init);
        CONFD_SET_INT8(vp, (int8_t)PyInt_AsLong(tmp));
        break;
    case C_INT16:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Int(init);
        CONFD_SET_INT16(vp, (int16_t)PyInt_AsLong(tmp)); break;
    case C_INT32:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Int(init);
        CONFD_SET_INT32(vp, (int32_t)PyInt_AsLong(tmp)); break;
    case C_INT64:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Long(init);
        CONFD_SET_INT64(vp, (int64_t)PyLong_AsLongLong(tmp)); break;
    case C_UINT8:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Int(init);
        CONFD_SET_UINT8(vp, (u_int8_t)PyInt_AsLong(tmp)); break;
    case C_UINT16:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Int(init);
        CONFD_SET_UINT16(vp, (u_int16_t)PyInt_AsLong(tmp)); break;
    case C_UINT32:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Long(init);
        CONFD_SET_UINT32(vp, (u_int32_t)PyLong_AsUnsignedLong(tmp)); break;
    case C_UINT64:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Long(init);
        CONFD_SET_UINT64(vp, (u_int64_t)PyLong_AsUnsignedLongLong(tmp));
        break;
    case C_DOUBLE:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Float(init);
        CONFD_SET_DOUBLE(vp, PyFloat_AsDouble(tmp));
        break;

    case C_IPV4:
        if (PyString_Check(init)) {
            struct in_addr ip;
            CONFD_PY_WITH_C_STR(init, src) {
                ret = inet_pton(AF_INET, src, &ip);
            }

            if (ret <= 0) {
                PyErr_Format(PyExc_ValueError, "Invalid IPv4 address");
                return -1;
            }

            CONFD_SET_IPV4(vp, ip);
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_IPV4 type must be a string");
            return -1;
        }
        break;

    case C_IPV6:
        if (PyString_Check(init)) {
            struct in6_addr ip6;
            CONFD_PY_WITH_C_STR(init, src) {
                ret = inet_pton(AF_INET6, src, &ip6);
            }

            if (ret <= 0) {
                PyErr_Format(PyExc_ValueError, "Invalid IPv6 address");
                return -1;
             }

            CONFD_SET_IPV6(vp, ip6);
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_IPV6 type must be a string");
            return -1;
        }
        break;

    case C_BOOL:
        if (PyBool_Check(init)) {
            if (init == Py_False) { CONFD_SET_BOOL(vp, 0); }
            else if (init == Py_True) { CONFD_SET_BOOL(vp, 1); }
            else goto badinit;
        } else if (PyNumber_Check(init)) {
            tmp = PyNumber_Long(init);
            if (PyLong_AsLong(tmp) != 0) {
                CONFD_SET_BOOL(vp, 1);
            } else {
                CONFD_SET_BOOL(vp, 0);
            }
        } else {
            goto badinit;
        }
        break;

    case C_QNAME:
        if (PyTuple_Check(init) && (PyTuple_Size(init) == 2)) {
            PyObject *prefix = PyTuple_GetItem(init, 0);
            PyObject *name = PyTuple_GetItem(init, 1);

            if (!(prefix == Py_None || PyString_Check(prefix))) {
                PyErr_Format(PyExc_ValueError,
                        "First item of tuple (prefix) must be a string "
                        "or None");
                return -1;
            }
            if (!PyString_Check(name)) {
                PyErr_Format(PyExc_ValueError,
                        "Second item of tuple (name) must be a string");
                return -1;
            }
            if (PyString_Size(name) < 1) {
                PyErr_Format(PyExc_ValueError,
                        "Second item of tuple (name) cannot be empty");
                return -1;
            }

            unsigned char *prefix_c = NULL, *name_c;
            unsigned int prefix_n = 0, name_n;

            if (PyString_Check(prefix)) {
                CONFD_PY_WITH_C_STR(prefix, prefix_c_str) {
                    prefix_c = (unsigned char*)strdup(prefix_c_str);
                    prefix_n = (unsigned int)strlen(prefix_c_str);
                }
            }

            CONFD_PY_WITH_C_STR(name, name_c_str) {
                name_c = (unsigned char*)strdup(name_c_str);
                name_n = (unsigned int)strlen(name_c_str);
            }

            CONFD_SET_QNAME(vp, prefix_c, prefix_n, name_c, name_n);
        }
        else {
            PyErr_Format(PyExc_ValueError, "A C_QNAME type must be a 2 tuple");
            return -1;
        }
        break;

    case C_DATETIME:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "dateTime");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError, "Invalid C_DATETIME string");
                return -1;
            }

        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_DATETIME type must be a string");
            return -1;
        }
        break;

    case C_DATE:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "date");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError, "Invalid C_DATE string");
                return -1;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_DATE type must be a string");
            return -1;
        }
        break;

    case C_TIME:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "time");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError, "Invalid C_TIME string");
                return -1;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_TIME type must be a string");
            return -1;
        }
        break;


    case C_DURATION:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "duration");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError, "Invalid C_DURATION string");
                return -1;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_DURATION type must be a string");
            return -1;
        }
        break;

    case C_ENUM_HASH:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Int(init);
        CONFD_SET_ENUM_HASH(vp, (int32_t) PyLong_AsLong(tmp));
        break;

    case C_BIT32:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Long(init);
        CONFD_SET_BIT32(vp, (u_int32_t)PyLong_AsUnsignedLong(tmp));
        break;

    case C_BIT64:
        if (!PyNumber_Check(init)) goto badinit;
        tmp = PyNumber_Long(init);
        CONFD_SET_BIT64(vp, (u_int64_t)PyLong_AsUnsignedLongLong(tmp));
        break;

    case C_BITBIG:
        if (PyByteArray_Check(init)) {
            size_t len = PyByteArray_Size(init);
            void *buf = malloc(len);
            if (buf == NULL) {
                PyErr_Format(PyExc_MemoryError, "buf == NULL");
                return -1;
            }
            memcpy(buf, PyByteArray_AsString(init), len);
            CONFD_SET_BITBIG(vp, buf, len);
        }
        else if (PyBytes_Check(init)) {
            size_t len = PyBytes_Size(init);
            void *buf = malloc(len);

            if (buf == NULL) {
                PyErr_Format(PyExc_MemoryError, "buf == NULL");
                return -1;
            }
            memcpy(buf, PyBytes_AsString(init), len);
            CONFD_SET_BITBIG(vp, buf, len);
        }
        else {
            PyErr_Format(PyExc_ValueError,
                         "A C_BITBIG type must be a bytearray or a bytes "
                         "object");
            return -1;
        }
        break;

    case C_LIST:
        if (PyList_Check(init)) {
            unsigned int size = (unsigned int)PyList_Size(init);
            unsigned int i;

            for (i = 0; i < size; ++i) {
                PyObject *li = PyList_GetItem(init, i);
                if (!PyConfd_Value_CheckExact(li)) {
                    PyErr_Format(PyExc_ValueError,
                        "A C_LIST type must be a list of Value's");
                    return -1;
                }
            }

            confd_value_t *list =
                (confd_value_t*)malloc(size * sizeof(confd_value_t));

            for (i = 0; i < size; ++i) {
                PyObject *li = PyList_GetItem(init, i);
                confd_value_dup_to(PyConfd_Value_PTR(li), &list[i]);
            }

            CONFD_SET_LIST(vp, list, size);
        }
        else {
            PyErr_Format(PyExc_ValueError,
                "A C_LIST type must be a list of Value's");
            return -1;
        }
        break;

    case C_OBJECTREF:
        if (isConfdHKeypathRef(init)) {
            confd_hkeypath_t *copy =
                confd_hkeypath_dup(((confdHKeypathRef*)init)->kp);
            CONFD_SET_OBJECTREF(vp, copy);
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_OBJECTREF type must be a HKeypathRef");
            return -1;
        }
        break;

    case C_UNION: goto nyitype;
    case C_PTR: goto nyitype;
    case C_CDBBEGIN: goto nyitype;

    case C_OID:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "oid");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError, "Invalid C_OID string");
                return -1;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_OID type must be a string");
            return -1;
        }
        break;


    case C_BINARY:
        if (PyBytes_Check(init)) {
            unsigned int len = (unsigned int) PyBytes_Size(init);

            void *buf = malloc(len);

            if (buf == NULL) {
                PyErr_Format(PyExc_MemoryError, "");
                return -1;
            }

            memcpy(buf, PyBytes_AsString(init), len);

            CONFD_SET_BINARY(vp, (unsigned const char *) buf, len);

        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_BINARY type must be a bytes instance");
            return -1;
        }
        break;

    case C_IPV4PREFIX :
    case C_IPV4_AND_PLEN:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "ipv4Prefix");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError,
                             "Invalid C_IPV4PREFIX string");
                return -1;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_IPV4PREFIX type must be a string");
            return -1;
        }
        break;

    case C_IPV6PREFIX :
    case C_IPV6_AND_PLEN:
        if (PyString_Check(init)) {
            struct confd_type *ct = confd_find_ns_type(0, "ipv6Prefix");
            CONFD_PY_WITH_C_STR(init, buf) {
                ret = confd_str2val(ct, buf, vp);
            }
            if (ret != CONFD_OK) {
                PyErr_Format(PyExc_ValueError,
                             "Invalid C_IPV6PREFIX string");
                return -1;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                "A C_IPV6PREFIX type must be a string");
            return -1;
        }
        break;


    case C_DECIMAL64 :
        if (PyTuple_Check(init) && (PyTuple_Size(init) == 2) &&
            _confd_is_int_or_long(PyTuple_GetItem(init, 0)) &&
            _confd_is_int_or_long(PyTuple_GetItem(init, 1))) {

            struct confd_decimal64 v;
            v.value = PyLong_AsLongLong(PyTuple_GetItem(init, 0));
            v.fraction_digits = PyLong_AsLongLong(PyTuple_GetItem(init, 1));

            CONFD_SET_DECIMAL64(vp, v);
        }
        else if (PyString_Check(init)) {
            struct confd_decimal64 v;

            CONFD_PY_WITH_C_STR(init, s) {
                ret = decimal64_init_str(s, &v);
            }

            if (ret) {
                PyErr_Format(PyExc_ValueError,
                             "invalid C_DECIMAL64 string '%s'", s);
                return -1;
            }
            CONFD_SET_DECIMAL64(vp, v);
        }
        else {
            PyErr_Format(PyExc_ValueError,
                        "A C_DECIMAL64 type must be a 2 int tuple or a string");

            return -1;
        }
        break;

    case C_IDENTITYREF:
        if (!PyTuple_Check(init)) goto badinit;
        if ((PyTuple_Size(init) != 2)) goto badinit;
        if (!PyNumber_Check(PyTuple_GetItem(init, 0))) goto badinit;
        if (!PyNumber_Check(PyTuple_GetItem(init, 1))) goto badinit;
        struct confd_identityref idref = {
                (u_int32_t)PyLong_AsLong(PyTuple_GetItem(init, 0)),
                (u_int32_t)PyLong_AsLong(PyTuple_GetItem(init, 1))
        };
        CONFD_SET_IDENTITYREF(vp, idref);
        break;

    case C_DQUAD: {
        struct confd_dotted_quad dquad;
        if (PyTuple_Check(init)) {
            if (dquad_from_tuple(init, &dquad))
                return -1;
        }
        else if (PyString_Check(init)) {
            if (dquad_from_string(init, &dquad))
                return -1;
        }
        else {
            goto badinit;
        }
        CONFD_SET_DQUAD(vp, dquad);
        break;
        }

    default:
        PyErr_Format(PyExc_ValueError,
                CONFD_PY_MODULE ".Value has no %d type", type);
        return -1;
    }

    /* release tmp if we used it */
    Py_XDECREF(tmp);
    self->ob_val.type = type;

    return 0;
badinit:
    /* FIXME: how to access name of type? */
    PyErr_Format(PyExc_ValueError,
            "illegal initialization parameter(s) for type %s(%d)",
             type2str(type), type);
    return -1;
nyitype:
    PyErr_Format(PyExc_ValueError, "type %s(%d) not yet implemented",
                 type2str(type), type);
    return -1;
}

static PyObject *
confdValue_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    return PY_TP_ALLOC(type);
}

static PyObject *confdValue_confd_type(PyConfd_Value_Object *self)
{
    return PyInt_FromLong((long) self->ob_val.type);
}

static PyObject *confdValue_confd_type_str(PyConfd_Value_Object *self)
{
    return PyString_FromString(type2str(self->ob_val.type));
}

static PyObject *confdValue_as_xmltag(PyConfd_Value_Object *self)
{
    const confd_value_t *v = &self->ob_val;

    if (v->type == C_XMLTAG) {
        return PyConfd_XmlTag_New(&(v->val.xmltag));
    } else {
        PyErr_Format(PyExc_TypeError, "not a C_XMLTAG value");
        return NULL;
    }
}

static PyObject *confdValue__size(PyConfd_Value_Object *self)
{
    const confd_value_t *v = &self->ob_val;

    if (v->type == C_BINARY) {
        return PyLong_FromLong(v->val.c_buf.size);
    }
    else if (v->type == C_LIST) {
        return PyLong_FromLong(v->val.list.size);
    }
    else {
        PyErr_Format(PyExc_TypeError,
                "len is not valid for this type");
        return NULL;
    }
}


static PyObject *confdValue_as_decimal64(PyConfd_Value_Object *self)
{
    const confd_value_t *v = &self->ob_val;

    if (v->type == C_DECIMAL64) {
        PyObject *ret = PyTuple_New(2);

        if (ret != NULL) {
            PyTuple_SetItem(ret, 0, PyLong_FromLongLong(v->val.d64.value));
            PyTuple_SetItem(ret, 1, PyInt_FromLong(v->val.d64.fraction_digits));
        }

        return ret;
    } else {
        PyErr_Format(PyExc_TypeError, "not a C_DECIMAL64 value");
        return NULL;
    }
}

static PyObject *confdValue_as_list(PyConfd_Value_Object *self)
{
    const confd_value_t *v = &self->ob_val;

    if (v->type == C_LIST) {
        return PyConfd_Value_New_DupTo_Py(v);
    } else {
        PyErr_Format(PyExc_TypeError, "not a C_LIST value");
        return NULL;
    }
}

static PyObject *confdValue_as_pyval(PyConfd_Value_Object *self)
{
    const confd_value_t *v = &self->ob_val;

    switch (v->type) {
        case C_XMLTAG:
        case C_XMLBEGIN:
        case C_XMLBEGINDEL:
        case C_XMLEND:
        case C_XMLMOVEFIRST:
        case C_XMLMOVEAFTER: {
            u_int32_t tag = v->val.xmltag.tag;
            u_int32_t ns = v->val.xmltag.ns;
            PyObject *t = PyTuple_New(2);
            PyTuple_SetItem(t, 0, PyInt_FromLong(tag));
            PyTuple_SetItem(t, 1, PyInt_FromLong(ns));
            return t;
            }

        case C_STR:
            return PyString_FromString(v->val.c_s);

        case C_BUF:
        case C_IPV4:
        case C_IPV4PREFIX:
        case C_IPV4_AND_PLEN:
        case C_IPV6:
        case C_IPV6PREFIX:
        case C_IPV6_AND_PLEN:
        case C_HEXSTR:
        case C_DATETIME:
        case C_DATE:
        case C_TIME:
        case C_OID:
        case C_DECIMAL64:
        case C_IDENTITYREF:
            return confdValue_str(self);

        case C_DURATION: {
            char *pdot;
            char buf[64];
            buf[sizeof(buf)-1] = 0;
            confd_pp_value(buf, sizeof(buf), v);
            if ((pdot = strstr(buf, ".")) != NULL)
                *pdot = 0;
            return PyString_FromString(buf);
            }

        case C_INT8:
        case C_INT16:
        case C_INT32:
        case C_UINT8:
        case C_UINT16:
        case C_UINT32:
        case C_BIT32:
        case C_ENUM_HASH:
            return confdValue_as_int(self);

        case C_INT64:
        case C_UINT64:
        case C_BIT64:
            return confdValue_as_long(self);

        case C_DOUBLE:
            return confdValue_as_float(self);

        case C_BOOL:
            if (CONFD_GET_BOOL(v))
                Py_RETURN_TRUE;
            else
                Py_RETURN_FALSE;

        case C_LIST: {
            unsigned int n = v->val.list.size;
            unsigned int c;

            PyObject *ret = PyList_New(n);

            for (c = 0; c < n; c++) {
                confd_value_t *item = (confd_value_t *) &v->val.list.ptr[c];
                PyConfd_Value_Object *tmp = PyConfd_Value_New_DupTo(item);
                PyList_SetItem(ret, c, confdValue_as_pyval(tmp));
                Py_DECREF(tmp);
            }
            return ret;
            }


        case C_OBJECTREF: {
            confd_hkeypath_t *dup;
            dup = confd_hkeypath_dup(v->val.hkp);
            return newConfdHKeypathRefAutoFree(dup);
            }

        case C_QNAME: {
            PyObject *t = PyTuple_New(2), *p, *n;
            if (v->val.qname.prefix.ptr) {
                p = PyString_FromStringAndSize(
                        (const char *)v->val.qname.prefix.ptr,
                        v->val.qname.prefix.size);
            }
            else {
                Py_INCREF(Py_None);
                p = Py_None;
            }
            n = PyString_FromStringAndSize(
                    (const char *)v->val.qname.name.ptr,
                    v->val.qname.name.size);
            PyTuple_SetItem(t, 0, p);
            PyTuple_SetItem(t, 1, n);
            return t;
            }

        case C_BINARY: {
            unsigned char *p = CONFD_GET_BINARY_PTR(v);
            unsigned int s = CONFD_GET_BINARY_SIZE(v);
            return PyBytes_FromStringAndSize((const char *)p, s);
            }

        case C_DQUAD: {
            struct confd_dotted_quad dquad = CONFD_GET_DQUAD(v);
            char buf[16];
            snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                     dquad.quad[0], dquad.quad[1],
                     dquad.quad[2], dquad.quad[3]);
            return PyString_FromString(buf);
            }

        case C_BITBIG:
            return PyByteArray_FromStringAndSize(
                    (const char *)CONFD_GET_BITBIG_PTR(v),
                    CONFD_GET_BITBIG_SIZE(v));

        case C_SYMBOL:
        case C_UNION:
        case C_CDBBEGIN:
        case C_PTR:
        case C_MAXTYPE:
        case C_NOEXISTS:
        case C_DEFAULT:
            return confdValue_confd_type_str(self);
    }
    return PyErr_Format(PyExc_ValueError, "as_pyval internal error (type=%s)",
                                          type2str(v->type));
}


static struct confd_type *cs_type_from_args(PyObject *schema_type)
{
    /* (ns, keypath) */
    if (PyTuple_Check(schema_type)) {
        if (PyTuple_Size(schema_type) != 2) {
            PyErr_Format(PyExc_ValueError,
                    "schema_type argument must be a 2-tuple of ns and keypath");
            return NULL;
        }

        PyObject *nso = PyTuple_GetItem(schema_type, 0);
        PyObject *kpo = PyTuple_GetItem(schema_type, 1);
        u_int32_t ns;

        if (PyInt_Check(nso)) {
            ns = (u_int32_t) PyInt_AsLong(nso);
        } else if (PyString_Check(nso)) {
            CONFD_PY_WITH_C_STR(nso, s) {
                ns = confd_str2hash(s);
            }
            if (ns == 0) {
                PyErr_Format(PyExc_ValueError, "Namespace %s not found", s);
                return NULL;
            }
        } else {
            PyErr_Format(PyExc_ValueError,
                    "Namespace must be an int or a string");
            return NULL;
        }
        if (!PyString_Check(kpo)) {
            PyErr_Format(PyExc_ValueError,
                    "Keypath must be a string");
            return NULL;
        }
        struct confd_cs_node *csroot = confd_find_cs_root(ns);

        if (csroot == NULL) {
            PyErr_Format(PyExc_ValueError, "Namespace %d not found", ns);
            return NULL;
        }

        struct confd_cs_node *node;
        CONFD_PY_WITH_C_STR(kpo, keypath) {
            node = confd_cs_node_cd(csroot, keypath);
        }
        if (node == NULL) {
            confdPyConfdError();
            return NULL;
        }

        return node->info.type;
    }

    /* CsNode */
    if (isConfdCsNode(schema_type))
        return ((confdCsNode*)schema_type)->node->info.type;

    /* CsType */
    if (isConfdCsType(schema_type))
        return ((confdCsType*)schema_type)->type;

    PyErr_Format(PyExc_ValueError,
            "schema_type argument must be either a 2-tuple (ns, keypath) or a "
            "CsNode instance or a CsType instance");
    return NULL;
}


/*
 * class method
 */
static PyObject *confdValue_str2val(PyConfd_Value_Object *cls,
                    PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "value",
        "schema_type",
        NULL
    };

    const char *value;
    PyObject *schema_type;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "sO", kwlist,
                &value, &schema_type)) {
        return NULL;
    }

    struct confd_type *type = cs_type_from_args(schema_type);

    if (type == NULL)
        return NULL;

    confd_value_t v;
    EXT_API_TIMING_CALL_WRAP(CHECK_CONFD_ERR(confd_str2val(type, value, &v)));

    PyObject *ret = (PyObject *) PyConfd_Value_New_DupTo(&v);
    confd_free_value(&v);

    return ret;
}

static PyObject *confdValue_val2str(PyConfd_Value_Object *self,
                    PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "schema_type",
        NULL
    };

    PyObject *schema_type;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &schema_type)) {
        return NULL;
    }

    struct confd_type *type = cs_type_from_args(schema_type);

    if (type == NULL)
        return NULL;

    char buf[INITIAL_BUF_SIZE];
    int res;
    PyObject *ret = NULL;

    EXT_API_TIMING_CALL_WRAP(
        CHECK_CONFD_ERR(res = confd_val2str(type, &(self->ob_val), buf,
                                            sizeof(buf))));

    if (res < INITIAL_BUF_SIZE) {
        ret = PyString_FromString(buf);
    } else {
        char *tmp = malloc(res+1);
        EXT_API_TIMING_CALL_WRAP(
            CHECK_CONFD_ERR_EXECERR(
                res = confd_val2str(type, &(self->ob_val), tmp, res+1),
                                    free(tmp)));
        ret = PyString_FromString(tmp);
        free(tmp);
    }

    return ret;
}

/* confdValue sequence methods */

static Py_ssize_t confdValue_sq_length(PyObject *self)
{
    const confd_value_t *v = &((PyConfd_Value_Object*)self)->ob_val;

    /* FIXME: handle more types here... */
    if (v->type == C_LIST)
        return v->val.list.size;

    return 0;
}

static PyObject *confdValue_sq_item(PyObject *self, Py_ssize_t index)
{
    const confd_value_t *v = &((PyConfd_Value_Object*)self)->ob_val;

    if (v->type != C_LIST) {
        PyErr_Format(PyExc_IndexError,
                "only a Value of type C_LIST can be indexed");
        return NULL;
    }

    if (index < 0 || index >= v->val.list.size) {
        PyErr_Format(PyExc_IndexError, "index out of range");
        return NULL;
    }

    confd_value_t *item = &v->val.list.ptr[index];

    return (PyObject*)PyConfd_Value_New_DupTo(item);
}

static PyMethodDef confdValue_methods[] = {
    MTH_DEF(confdValue, confd_type, METH_NOARGS),
    MTH_DEF(confdValue, confd_type_str, METH_NOARGS),
    MTH_DEF(confdValue, _size, METH_NOARGS),
    MTH_DEF(confdValue, as_xmltag, METH_NOARGS),
    MTH_DEF(confdValue, as_decimal64, METH_NOARGS),
    MTH_DEF(confdValue, as_list, METH_NOARGS),
    MTH_DEF(confdValue, as_pyval, METH_NOARGS),
    MTH_DEF(confdValue, str2val, METH_VARARGS | METH_KEYWORDS | METH_CLASS),
    MTH_DEF(confdValue, val2str, METH_VARARGS | METH_KEYWORDS),

    {NULL}  /* Sentinel */
};

static int setup_type_confd_value(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdValue_new },
        { .slot = Py_tp_init,        .pfunc = confdValue_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdValue_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdValue_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdValue__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdValue_repr },
        { .slot = Py_tp_str,         .pfunc = confdValue_str },
        { .slot = Py_nb_bool,        .pfunc = confdValue_nonzero },
        { .slot = Py_nb_int,         .pfunc = confdValue_as_long },
        { .slot = Py_nb_float,       .pfunc = confdValue_as_float },
        { .slot = Py_sq_length,      .pfunc = confdValue_sq_length },
        { .slot = Py_sq_item,        .pfunc = confdValue_sq_item },
        { .slot = Py_tp_iter,        .pfunc = confdValue_iter },
        { .slot = Py_tp_richcompare, .pfunc = confdValue_richcompare },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".Value",
        .basicsize = sizeof(PyConfd_Value_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdValueType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdValue(confd_value_t *v)
{
    PyConfd_Value_Object *self =
        PyObject_New(PyConfd_Value_Object, confdValueType);

    if (self != NULL) {
        confd_value_dup_to(v, PyConfd_Value_PTR(self));
    }

    return (PyObject *) self;
}

PyConfd_Value_Object *PyConfd_Value_New_DupTo(const confd_value_t *v)
{
    PyConfd_Value_Object *self = PyConfd_Value_New_NoInit();

    if (self != NULL) {
        confd_value_dup_to(v, PyConfd_Value_PTR(self));
    }

    return self;
}

// Like PyConfd_Value_New_DupTo(...) but ...
//  - C_LIST become a Python list of PyConfd_Value_Objects
PyObject *PyConfd_Value_New_DupTo_Py(const confd_value_t *v)
{
    if (v->type == C_LIST) {
        unsigned int n = v->val.list.size;
        unsigned int c;

        PyObject *ret = PyList_New(n);

        if (ret != NULL) {
            for (c = 0; c < n; c++) {
                confd_value_t *item = (confd_value_t *) &v->val.list.ptr[c];
                PyList_SetItem(ret, c,
                        (PyObject *) PyConfd_Value_New_DupTo(item));
            }
        }

        return ret;
    } else {
        return (PyObject *) PyConfd_Value_New_DupTo(v);
    }
}

/* Converts an array of confd_value_t to a python list of PyConfd_Value */
PyObject *PyConfd_Values_New_DupTo_PyList(
        const confd_value_t *values, int num)
{
    int i;
    PyObject *pylist = PyList_New(num);

    for (i = 0; i < num; i++) {
        PyList_SetItem(pylist,
                       i,
                       (PyObject*)PyConfd_Value_New_DupTo(&values[i]));
    }

    return pylist;
}


PyConfd_Value_Object *PyConfd_Value_New_NoInit(void)
{
    PyConfd_Value_Object *self =
        PyObject_New(PyConfd_Value_Object, confdValueType);
    memset(PyConfd_Value_PTR(self), 0, sizeof(confd_value_t));
    return self;
}

int PyConfd_Value_CheckExact(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdValueType);
}

/* Function that can be passed to PyArg_ParseTuple() using the 'O' format */

int confdValue_arg(PyObject *arg, void *p)
{
    PyConfd_Value_Object **vp = (PyConfd_Value_Object **)p;
    PyConfd_Value_Object *new;

    if (PyConfd_Value_CheckExact(arg)) {
        Py_INCREF(arg);
        *vp = (PyConfd_Value_Object *)arg;
        return 1;
    }

    if ((new = PyConfd_Value_New_NoInit()) == NULL) {
        return 0;
    }
    *vp = new;
    return 1;
}


/* ************************************************************************ */
/* confd_tag_value_t -> confd.TagValue                             */
/* ************************************************************************ */

static void confdTagValue_dealloc(PyConfd_TagValue_Object *self)
{
    confd_free_value(&self->tv.v);

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdTagValue_repr(PyConfd_TagValue_Object *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".TagValue(tag=%i, ns=%i)",
                              self->tv.tag.tag, self->tv.tag.ns);
}

static PyObject *confdTagValue_str(PyConfd_TagValue_Object *self)
{
    char *s = confd_hash2str(self->tv.tag.tag);

    if (s)
        return PyString_FromString(s);
    else
        return confdTagValue_repr(self);
}

static int confdTagValue_init(PyConfd_TagValue_Object *self,
                              PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "xmltag",
        "v",
        "tag",
        "ns",
        NULL
    };


    int tag = 0;
    int ns = 0;
    PyConfd_XmlTag_Object *xmltag = NULL;
    PyConfd_Value_Object *value = NULL;

    int argCount = (int) PyTuple_Size(args);

    if (!PyArg_ParseTupleAndKeywords(args, kwds,
                "|OOii", kwlist, &xmltag, &value, &tag, &ns)) {
        return -1;
    }

    if (kwds && PyDict_CheckExact(kwds)) {
        argCount += (int) PyDict_Size(kwds);
    }

    if (argCount != 2) {
        PyErr_Format(PyExc_TypeError,
            "Two arguments must be specified, either xmltag and v "
            "or tag and ns");
        return -1;
    }


    if (kwds) {
        if (!(
               (PyDict_GetItemString(kwds, "xmltag") &&
                PyDict_GetItemString(kwds, "v"))
               ||
               (PyDict_GetItemString(kwds, "tag") &&
                PyDict_GetItemString(kwds, "ns"))
            )) {

            PyErr_Format(PyExc_TypeError,
                "Either xmltag and v or tag and ns must be specified");

            return -1;
        }
    }

    if (xmltag && !PyConfd_XmlTag_CheckExact((PyObject *) xmltag)) {
        PyErr_Format(PyExc_TypeError,
            "xmltag argument must be a "
            CONFD_PY_MODULE ".XmlTag instance");

        return -1;
    }

    if (value && !PyConfd_Value_CheckExact((PyObject *)value)) {
        PyErr_Format(PyExc_TypeError,
            "v argument must be a "
            CONFD_PY_MODULE ".Value instance");

        return -1;
     }

    if (xmltag) {
        self->tv.tag.ns = xmltag->ns;
        self->tv.tag.tag = xmltag->tag;
    }


    if (value) {
        if (confd_value_dup_to(PyConfd_Value_PTR(value), &self->tv.v) == NULL) {
            return -1;
        }
    } else {
        self->tv.v.type = C_NOEXISTS;

        self->tv.tag.ns = ns;
        self->tv.tag.tag = tag;
    }


    return 0;
}

static PyObject *
confdTagValue_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyObject *self = PY_TP_ALLOC(type);

    ((PyConfd_TagValue_Object*)self)->tv.v.type = C_NOEXISTS;

    return self;
}

static PyObject *confdTagValue_getattro(PyConfd_TagValue_Object *self,
                    PyObject *name_)
{
    int ret;

    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    CONFD_PY_WITH_C_STR(name_, name) {
        ret = strcmp(name, "v");
    }

    if (ret == 0) {
        return newConfdValue(&self->tv.v);
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyMemberDef confdTagValue_members[] = {
    {"ns", T_UINT, offsetof(PyConfd_TagValue_Object, tv.tag.ns), READONLY,
     confdTagValue_attr_ns__doc__},

    {"tag", T_UINT, offsetof(PyConfd_TagValue_Object, tv.tag.tag), READONLY,
     confdTagValue_attr_tag__doc__},

    {NULL}  /* Sentinel */
};


static PyMethodDef confdTagValue_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_tagvalue(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdTagValue_new },
        { .slot = Py_tp_init,        .pfunc = confdTagValue_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdTagValue_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdTagValue_methods },
        { .slot = Py_tp_members,     .pfunc = confdTagValue_members },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdTagValue__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdTagValue_repr },
        { .slot = Py_tp_str,         .pfunc = confdTagValue_str },
        { .slot = Py_tp_getattro,    .pfunc = confdTagValue_getattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".TagValue",
        .basicsize = sizeof(PyConfd_TagValue_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdTagValueType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* PyConfd_TagValue_New(confd_tag_value_t *tv)
{
    PyConfd_TagValue_Object *self = (PyConfd_TagValue_Object*)
        PyObject_New(PyConfd_TagValue_Object, confdTagValueType);

    if (self != NULL) {
        self->tv.tag = tv->tag;
        confd_value_dup_to(&(tv->v), &(self->tv.v));
    }

    return (PyObject *) self;
}

int PyConfd_TagValue_CheckExact(PyObject *o)
{
    return o->ob_type == confdTagValueType;
}

/* ************************************************************************* */
/* Python PyConfd_TagValue_Object list helper functions                      */
/* ************************************************************************* */

void init_py_confd_tag_value_t_list(py_confd_tag_value_t_list_t *sl)
{
    sl->size = 0;
    sl->list = NULL;
}

int alloc_py_confd_tag_value_t_list(
        PyObject *o, py_confd_tag_value_t_list_t *sl, const char argname[])
{
    if (o == Py_None) {
        return 1;
    }

    if (!PyList_CheckExact(o)) {
        PyErr_Format(PyExc_TypeError, "%s argument must be a list", argname);
        return 0;
    }

    sl->size = (int) PyList_Size(o);
    sl->list = malloc(sl->size * sizeof(confd_tag_value_t));

    if (sl->list == NULL) {
        PyErr_Format(PyExc_MemoryError, "sl->list == NULL");
        return 0;
    }

    int c;

    for (c = 0; c < sl->size; c++) {
        PyObject *item = PyList_GetItem(o, c);

        if (!PyConfd_TagValue_CheckExact(item)) {
            PyErr_Format(PyExc_TypeError,
                    "%s[%d] must be a "
                    CONFD_PY_MODULE ".TagValue instance",
                    argname, (int) c);

            free(sl->list);
            sl->list = NULL;

            return 0;
        }

        memcpy(&(sl->list[c]),
               PyConfd_TagValue_PTR(item),
               sizeof(confd_tag_value_t));
    }

    return 1;
}

void free_py_confd_tag_value_t_list(py_confd_tag_value_t_list_t *sl)
{
    if (sl->list != NULL) {
        free(sl->list);
    }
}

/* ************************************************************************ */
/* confd_attr_value_t -> confd.AttrValue                             */
/* ************************************************************************ */

static void confdAttrValue_dealloc(PyConfd_AttrValue_Object *self)
{
    Py_XDECREF(self->attr);
    Py_XDECREF(self->v);

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdAttrValue_str(PyConfd_AttrValue_Object *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".AttrValue");
}


static PyObject *confdAttrValue_repr(PyConfd_AttrValue_Object *self)
{
    return confdAttrValue_str(self);
}

static int confdAttrValue_init(PyConfd_AttrValue_Object *self,
                              PyObject *args, PyObject *kwds)
{

    return 0;
}

static PyObject *
confdAttrValue_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "attr",
        "v",
        NULL
    };

    long attr;
    PyObject *value;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "lO", kwlist,
                &attr, &value)) {
        return NULL;
    }

    if (!PyConfd_Value_CheckExact(value)) {
        PyErr_Format(PyExc_TypeError,
                "v argument must be an "
                CONFD_PY_MODULE ".Value instance");
        return NULL;
    }

    PyConfd_AttrValue_Object *self =
        (PyConfd_AttrValue_Object*)PY_TP_ALLOC(type);

    self->attr = PyLong_FromLong(attr);
    self->v = value;

    return (PyObject *) self;
}

static PyMemberDef confdAttrValue_members[] = {
    {"attr", T_OBJECT_EX, offsetof(PyConfd_AttrValue_Object, attr), READONLY,
     confdAttrValue_attr_attr__doc__},

    {"v", T_OBJECT_EX, offsetof(PyConfd_AttrValue_Object, v), READONLY,
     confdAttrValue_attr_v__doc__},

    {NULL}  /* Sentinel */
};


static PyMethodDef confdAttrValue_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_attrvalue(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdAttrValue_new },
        { .slot = Py_tp_init,        .pfunc = confdAttrValue_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdAttrValue_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdAttrValue_methods },
        { .slot = Py_tp_members,     .pfunc = confdAttrValue_members },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdAttrValue__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdAttrValue_repr },
        { .slot = Py_tp_str,         .pfunc = confdAttrValue_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".AttrValue",
        .basicsize = sizeof(PyConfd_AttrValue_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdAttrValueType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdAttrValueType == NULL)
        return -1;
    return 0;
}

PyObject* PyConfd_AttrValue_New_DupTo(const confd_attr_value_t *av)
{
    PyConfd_AttrValue_Object *self = (PyConfd_AttrValue_Object*)
        PyObject_New(PyConfd_AttrValue_Object, confdAttrValueType);

    if (self != NULL) {
        self->attr = (PyObject *) PyLong_FromLong(av->attr);
        self->v = (PyObject *) PyConfd_Value_New_DupTo(&av->v);
    }

    return (PyObject *) self;
}

PyObject* PyConfd_AttrValue_New_DupTo_Py(const confd_attr_value_t *av)
{
    PyConfd_AttrValue_Object *self = (PyConfd_AttrValue_Object*)
        PyObject_New(PyConfd_AttrValue_Object, confdAttrValueType);

    if (self != NULL) {
        self->attr = (PyObject *) PyLong_FromLong(av->attr);
        self->v = PyConfd_Value_New_DupTo_Py(&av->v);
    }

    return (PyObject *) self;
}


int PyConfd_AttrValue_CheckExact(PyObject *o)
{
    return o->ob_type == confdAttrValueType;
}


/* ************************************************************************ */
/* struct xml_tag -> confd.XmlTag                                     */
/* ************************************************************************ */


static void confdXmlTag_dealloc(PyConfd_XmlTag_Object *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}


static PyObject *confdXmlTag_repr(PyConfd_XmlTag_Object *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".XmlTag(tag=%d, ns=%d)",
            self->tag, self->ns);
}

static PyObject *confdXmlTag_str(PyConfd_XmlTag_Object *self)
{
    char *s = confd_hash2str(self->tag);
    if (s) {
        /* schema information is loaded */
        return PyString_FromString(s);
    }

    return confdXmlTag_repr(self);
}

static int confdXmlTag_init(PyConfd_XmlTag_Object *self,
        PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "ns",
        "tag",
        NULL
    };

    u_int32_t ns;
    u_int32_t tag;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "II", kwlist, &ns, &tag)) {
        return -1;
    }

    if (self != NULL) {
        self->ns = ns;
        self->tag = tag;
    }

    return 0;
}

static PyObject *
confdXmlTag_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    return PY_TP_ALLOC(type);
}

static PyMethodDef confdXmlTag_methods[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef confdXmlTag_members[] = {
    {"ns", T_UINT, offsetof(PyConfd_XmlTag_Object, ns), READONLY,
     confdXmlTag_attr_ns__doc__},

    {"tag", T_UINT, offsetof(PyConfd_XmlTag_Object, tag), READONLY,
     confdXmlTag_attr_tag__doc__},

    {NULL}  /* Sentinel */
};

static int setup_type_confd_xmltag(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdXmlTag_new },
        { .slot = Py_tp_init,        .pfunc = confdXmlTag_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdXmlTag_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdXmlTag_methods },
        { .slot = Py_tp_members,     .pfunc = confdXmlTag_members },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdXmlTag__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdXmlTag_repr },
        { .slot = Py_tp_str,         .pfunc = confdXmlTag_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".XmlTag",
        .basicsize = sizeof(PyConfd_XmlTag_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdXmlTagType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* PyConfd_XmlTag_New(const struct xml_tag *xmltag)
{
    PyConfd_XmlTag_Object *self = (PyConfd_XmlTag_Object*)
        PyObject_New(PyConfd_XmlTag_Object, confdXmlTagType);

    self->ns = xmltag->ns;
    self->tag = xmltag->tag;

    return (PyObject *) self;
}

int PyConfd_XmlTag_CheckExact(PyObject *o)
{
    //return PyObject_TypeCheck(o, &confdXmlTagType);
    return o->ob_type == confdXmlTagType;
}

/* ************************************************************************ */
/* confd_hkeypath_t * -> confd.HKeypathRef                            */
/* ************************************************************************ */

/* Code ripped from confd_internal.c
 *
 * Patched to add namespace prefixes
 */

extern int pp_keyval(char *buf, int n, const confd_value_t *v, int ns);
extern int keyval2str(struct confd_type *type, const confd_value_t *v,
                      char *buf, int n);
extern int confd_snprintf(char *dst, int n, char *format, ...);

#define INC_CONFD_SNPRINTF(buf, n, tot, ...) \
        do { \
            int _k = confd_snprintf((buf), (n), __VA_ARGS__); \
            (n) -= _k; (buf) += _k; (tot) += _k; \
        } while(0)

int hkeypath2str(char *buf, int n, const confd_hkeypath_t *hkeypath, int kp_len)
{
    int tmplen = 0;
    int pos;
    uint32_t ns = 0;
    int len = 0;

    if (n < 0)
        n = 0;

    if (kp_len == 0)
        return confd_snprintf(buf, n, "/");

    for (pos=hkeypath->len-1; pos >= hkeypath->len - kp_len ; pos--) {
        const confd_value_t *v = &(hkeypath->v[pos][0]);
        if (v->type == C_XMLTAG) {
            INC_CONFD_SNPRINTF(buf, n, len, "/");
            if (v->val.xmltag.ns != 0 && v->val.xmltag.ns != ns) {
                ns = v->val.xmltag.ns;
                /* possibly append prefix */
                char *prefix = confd_ns2prefix(ns);
                if (prefix) {
                    INC_CONFD_SNPRINTF(buf, n, len, "%s:", prefix);
                }
            }
            tmplen = confd_pp_value(buf, n, v);
            len += tmplen;
            buf += tmplen;
            n -= tmplen;
        }
        else if (v->type == C_NOEXISTS) {
            /* empty key value (for chk_data_access() callback) */
            INC_CONFD_SNPRINTF(buf, n, len, "{}");
        } else {
            /* it's a key value */
            int i = 0;
            struct confd_cs_node *node;
            struct confd_cs_node *key = NULL;

            INC_CONFD_SNPRINTF(buf, n, len, "{");
            node = confd_find_cs_node(hkeypath, hkeypath->len - pos);

            if (node != NULL && node->info.keys != NULL)
                key = node->children;
            while (1) {
                if (key == NULL || key->info.type == NULL) {
                    /* fall back to non-schema-aware method */
                    tmplen = pp_keyval(buf, n, v, ns);
                }
                else if ((tmplen = keyval2str(key->info.type, v, buf, n)) < 0) {
                    /* fall back to non-schema-aware method */
                    tmplen = pp_keyval(buf, n, v, ns);
                }
                if (key != NULL)
                    key = key->next;
                len += tmplen;
                buf += tmplen;
                n -= tmplen;

                v = &(hkeypath->v[pos][++i]);
                if (v->type == C_NOEXISTS)
                    break;
                INC_CONFD_SNPRINTF(buf, n, len, " ");

            }
            INC_CONFD_SNPRINTF(buf, n, len, "}");
        }
    }
    return len;
}

#undef INC_CONFD_SNPRINTF

#define VALIDATE_HKEYPATHREF(hkp) { \
    if (hkp->kp == NULL) { \
        PyErr_Format(PyExc_TypeError, "HKeypathRef is no longer valid"); \
        return 0; \
    } \
}


static void confdHKeypathRef_dealloc(confdHKeypathRef *self)
{
    if (self->autoFree && (self->kp != NULL)) {
        confd_free_hkeypath(self->kp);
    }

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdHKeypathRef_str(PyObject *self)
{
    confdHKeypathRef *hkp = (confdHKeypathRef*)self;
    VALIDATE_HKEYPATHREF(hkp);
    return _confd_hkeypath2PyString(hkp->kp, hkp->kp->len);
}


static PyObject *confdHKeypathRef_repr(confdHKeypathRef *self)
{
    VALIDATE_HKEYPATHREF(self);
    return PyString_FromFormat(
            CONFD_PY_MODULE ".HKeypathRef : len=%d",
            self->kp->len);
}

static int confdHKeypathRef_init(confdHKeypathRef *self,
                                 PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdHKeypathRef_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".HKeypathRef from Python");

    return NULL;
}

/*
 * HKeypathRef sequence methods
 */
static Py_ssize_t confdHKeypathRef_sq_length(PyObject *self)
{
    confdHKeypathRef *hkp = (confdHKeypathRef*)self;
    if (hkp->kp)
        return hkp->kp->len;
    else
        return 0;
}

static PyObject *confdHKeypathRef_sq_item(PyObject *self, Py_ssize_t index)
{
    confdHKeypathRef *hkp = (confdHKeypathRef*)self;
    VALIDATE_HKEYPATHREF(hkp);

    if (index < 0 || index >= hkp->kp->len) {
        PyErr_Format(PyExc_IndexError, "index out of range");
        return NULL;
    }

    confd_value_t *item = hkp->kp->v[index];

    /* tag value */
    if (item[0].type == C_XMLTAG) {
        return PyConfd_XmlTag_New(&item[0].val.xmltag);
    }

    int count = 0;
    while (item[count].type != C_NOEXISTS) {
        count++;
    }

    PyObject *t = PyTuple_New(count);
    int i;
    for (i = 0; i < count; i++) {
        PyTuple_SetItem(t, i, (PyObject*)PyConfd_Value_New_DupTo(&item[i]));
    }

    return t;
}

static PyObject *confdHKeypathRef_sq_slice(
        PyObject *self, Py_ssize_t low, Py_ssize_t high)
{
    confdHKeypathRef *hkp = (confdHKeypathRef*)self;
    VALIDATE_HKEYPATHREF(hkp);

    if (hkp->kp->len != (int)high) {
        PyErr_Format(PyExc_TypeError,
                "HKeypathRef slices must include the last element");
        return NULL;
    }

    confd_hkeypath_t *dup;

    EXT_API_TIMING_CALL_WRAP(
        CONFD_EXEC(dup = confd_hkeypath_dup_len(hkp->kp, high - low)));

    return newConfdHKeypathRefAutoFree(dup);
}


static PyObject *confdHKeypathRef_mp_subscript(PyObject *self, PyObject *item)
{
    confdHKeypathRef *hkp = (confdHKeypathRef*)self;

    if (PyInt_Check(item)) {
        Py_ssize_t i;
        i = PyNumber_AsSsize_t(item, PyExc_IndexError);
        if (i == -1 && PyErr_Occurred())
            return NULL;
        if (i < 0)
            i += hkp->kp->len;
        return confdHKeypathRef_sq_item(self, i);
    }
    else if (PySlice_Check(item)) {
        Py_ssize_t start, stop, step, slicelength;

        if (PySlice_GetIndicesEx(item, hkp->kp->len,
                                 &start, &stop, &step, &slicelength) < 0) {
            return NULL;
        }

        if (step == 1) {
            return confdHKeypathRef_sq_slice(self, start, stop);
        }
        else {
            PyErr_Format(PyExc_TypeError,
                    "HKeypathRef slice steps not supported");
            return NULL;
        }
    }
    else {
        PyErr_Format(PyExc_TypeError, "HKeypathRef indices must be integers");
        return NULL;
    }
}

static PyObject *confdHKeypathRef_internal_dup(confdHKeypathRef *hkp, int len)
{
    confd_hkeypath_t *dup;
    EXT_API_TIMING_CALL_WRAP(
        CONFD_EXEC(dup = confd_hkeypath_dup_len(hkp->kp, len)));
    return newConfdHKeypathRefAutoFree(dup);
}

static PyObject *confdHKeypathRef_dup(PyObject *self)
{
    confdHKeypathRef *hkp = (confdHKeypathRef*)self;
    VALIDATE_HKEYPATHREF(hkp);
    return confdHKeypathRef_internal_dup(hkp, hkp->kp->len);
}

static PyObject *confdHKeypathRef_dup_len(
        PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "len",
        NULL
    };

    confdHKeypathRef *hkp = (confdHKeypathRef*)self;
    VALIDATE_HKEYPATHREF(hkp);
    int len;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &len))
        return NULL;

    if (len < 0 || len > hkp->kp->len) {
        PyErr_Format(PyExc_IndexError, "index out of range");
        return NULL;
    }

    return confdHKeypathRef_internal_dup(hkp, len);
}

static PyMethodDef confdHKeypathRef_methods[] = {
    MTH_DEF(confdHKeypathRef, dup, METH_NOARGS),
    MTH_DEF(confdHKeypathRef, dup_len, METH_VARARGS | METH_KEYWORDS),
    {NULL}  /* Sentinel */
};

static int setup_type_confd_hkeypathref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdHKeypathRef_new },
        { .slot = Py_tp_init,        .pfunc = confdHKeypathRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdHKeypathRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdHKeypathRef_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdHKeypathRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdHKeypathRef_repr },
        { .slot = Py_tp_str,         .pfunc = confdHKeypathRef_str },
        { .slot = Py_sq_length,      .pfunc = confdHKeypathRef_sq_length },
        { .slot = Py_sq_item,        .pfunc = confdHKeypathRef_sq_item },
        { .slot = Py_mp_subscript,   .pfunc = confdHKeypathRef_mp_subscript },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".HKeypathRef",
        .basicsize = sizeof(confdHKeypathRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdHKeypathRefType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdHKeypathRefAutoFree(confd_hkeypath_t *kp)
{
    if (kp == NULL)
        Py_RETURN_NONE;

    confdHKeypathRef *self = (confdHKeypathRef*)
        PyObject_New(confdHKeypathRef, confdHKeypathRefType);

    self->kp = kp;
    self->autoFree = 1;

    return (PyObject *) self;
}

PyObject* newConfdHKeypathRefNoAutoFree(confd_hkeypath_t *kp)
{
    if (kp == NULL)
        Py_RETURN_NONE;

    confdHKeypathRef *self = (confdHKeypathRef*)
        PyObject_New(confdHKeypathRef, confdHKeypathRefType);

    self->kp = kp;
    self->autoFree = 0;

    return (PyObject *) self;
}

void unrefConfdHKeypathRef(PyObject *kpref)
{
    if (kpref == NULL || kpref == Py_None)
        return;
    ((confdHKeypathRef*) kpref)->kp = NULL;
}

int isConfdHKeypathRef(PyObject *o)
{
    return PyObject_TypeCheck(o, confdHKeypathRefType);
}


/* ************************************************************************ */
/* struct confd_tr_item* -> _confd.dp.TrItemRef                             */
/* ************************************************************************ */

static void confdTrItemRef_dealloc(confdTrItemRef *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdTrItemRef_str(confdTrItemRef *self)
{
    char *str = _confd_hkeypath2str(self->tr->hkp, self->tr->hkp->len);
    PyObject *py_str = PyString_FromFormat(
                CONFD_PY_MODULE ".dp.TrItemRef(callpoint=%s, op=%d, kp=%s)",
                self->tr->callpoint, self->tr->op, str);
    free(str);
    return py_str;
}

static PyObject *confdTrItemRef_repr(confdTrItemRef *self)
{
    return confdTrItemRef_str(self);
}

static int confdTrItemRef_init(confdTrItemRef *self,
                               PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdTrItemRef_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.TrItemRef from Python");

    return NULL;
}

static PyObject *confdTrItemRef_getattro_c_str(confdTrItemRef *self,
                                               PyObject *name_,
                                               const char *name)
{
    if (strcmp(name, "callpoint") == 0) {
        return PyString_FromString(self->tr->callpoint);
    } else if (strcmp(name, "op") == 0) {
        return PyInt_FromLong((long)self->tr->op);
    } else if (strcmp(name, "hkp") == 0) {
        return newConfdHKeypathRefNoAutoFree(self->tr->hkp);
    } else if (strcmp(name, "val") == 0) {
        if (self->tr->val) {
            return newConfdValue(self->tr->val);
        } else {
            Py_RETURN_NONE;
        }
    } else if (strcmp(name, "choice") == 0) {
        if (self->tr->choice) {
            return newConfdValue(self->tr->choice);
        } else {
            Py_RETURN_NONE;
        }
    } else if (strcmp(name, "attr") == 0) {
        return PyLong_FromUnsignedLong((unsigned long) self->tr->attr);
    } else if (strcmp(name, "next") == 0) {
        if (self->tr->next) {
            return newConfdTrItemRef(self->tr->next);
        } else {
            Py_RETURN_NONE;
        }
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyObject *confdTrItemRef_getattro(confdTrItemRef *self,
                                         PyObject *name_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    PyObject *res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = confdTrItemRef_getattro_c_str(self, name_, name);
    }
    return res;
}

static PyMethodDef confdTrItemRef_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_tritemref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdTrItemRef_new },
        { .slot = Py_tp_init,        .pfunc = confdTrItemRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdTrItemRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdTrItemRef_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdTrItemRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdTrItemRef_repr },
        { .slot = Py_tp_str,         .pfunc = confdTrItemRef_str },
        { .slot = Py_tp_getattro,    .pfunc = confdTrItemRef_getattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.TrItemRef",
        .basicsize = sizeof(confdTrItemRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdTrItemRefType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdTrItemRef(struct confd_tr_item *tr)
{
    confdTrItemRef *self = (confdTrItemRef*)
        PyObject_New(confdTrItemRef, confdTrItemRefType);

    self->tr = tr;

    return (PyObject *) self;
}

int isConfdTrItemRef(PyObject *o)
{
    return PyObject_TypeCheck(o, confdTrItemRefType);
}




/* ************************************************************************ */
/* struct confd_trans_ctx* -> confd.TransCtxRef                       */
/* ************************************************************************ */


static void confdTransCtxRef_dealloc(confdTransCtxRef *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdTransCtxRef_str(confdTransCtxRef *self)
{
    return PyString_FromFormat(
                CONFD_PY_MODULE ".TransCtxRef : fd=%d : vfd=%d : th=%d",
                self->tc->fd, self->tc->vfd, self->tc->thandle);
}


static PyObject *confdTransCtxRef_repr(confdTransCtxRef *self)
{
    return confdTransCtxRef_str(self);
}

static int confdTransCtxRef_init(confdTransCtxRef *self,
                                 PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdTransCtxRef_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".TransCtxRef from Python");

    return NULL;
}

static PyObject *confdTransCtxRef_getattro_c_str(confdTransCtxRef *self,
                                                 PyObject *name_,
                                                 const char *name)
{
    if (strcmp(name, "fd") == 0) {
        return PyInt_FromLong((long)self->tc->fd);
    } else if (strcmp(name, "th") == 0) {
        return PyInt_FromLong((long)self->tc->thandle);
    } else if (strcmp(name, "secondary_index") == 0) {
        return PyInt_FromLong((long)self->tc->secondary_index);
    } else if (strcmp(name, "username") == 0) {
        return PyString_FromString(self->tc->uinfo->username);
    } else if (strcmp(name, "context") == 0) {
        return PyString_FromString(self->tc->uinfo->context);
    } else if (strcmp(name, "uinfo") == 0) {
        return newConfdUserInfo(self->tc->uinfo);
    } else if (strcmp(name, "accumulated") == 0) {
        if (self->tc->accumulated) {
            return newConfdTrItemRef(self->tc->accumulated);
        } else {
            Py_RETURN_NONE;
        }
    } else if (strcmp(name, "traversal_id") == 0) {
        return PyInt_FromLong(self->tc->traversal_id);
    } else if (strcmp(name, "cb_flags") == 0) {
        return PyInt_FromLong(self->tc->cb_flags);
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyObject *confdTransCtxRef_getattro(confdTransCtxRef *self,
                                           PyObject *name_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    PyObject *res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = confdTransCtxRef_getattro_c_str(self, name_, name);
    }
    return res;
}

static int confdTransCtxRef_setattro_c_str(confdTransCtxRef *self,
                                           PyObject *name_, PyObject *val_,
                                           const char *name)
{
    if (strcmp(name, "cb_flags") == 0) {
        if (val_ == NULL) {
            PyErr_Format(PyExc_TypeError, "cb_flags can not be deleted");
            return 1;
        }

        int val = PyInt_AsLong(val_);
        if (val == -1 && PyErr_Occurred()) {
            PyErr_Format(PyExc_TypeError, "val must be a number");
            return 1;
        }

        self->tc->cb_flags = val;
        return 0;
    }

    PyErr_Format(PyExc_AttributeError, "%s is read only", name);
    return 1;
}

static int confdTransCtxRef_setattro(confdTransCtxRef *self,
                                     PyObject *name_, PyObject *val_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return 1;
    }

    int res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = confdTransCtxRef_setattro_c_str(self, name_, val_, name);
    }
    return res;
}

static PyMethodDef confdTransCtxRef_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_transctxref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdTransCtxRef_new },
        { .slot = Py_tp_init,        .pfunc = confdTransCtxRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdTransCtxRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdTransCtxRef_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdTransCtxRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdTransCtxRef_repr },
        { .slot = Py_tp_str,         .pfunc = confdTransCtxRef_str },
        { .slot = Py_tp_getattro,    .pfunc = confdTransCtxRef_getattro },
        { .slot = Py_tp_setattro,    .pfunc = confdTransCtxRef_setattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".TransCtxRef",
        .basicsize = sizeof(confdTransCtxRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdTransCtxRefType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdTransCtxRef(struct confd_trans_ctx *tc)
{
    confdTransCtxRef *self = (confdTransCtxRef*)
        PyObject_New(confdTransCtxRef, confdTransCtxRefType);

    self->tc = tc;

    return (PyObject *) self;
}

int isConfdTransCtxRef(PyObject *o)
{
    return PyObject_TypeCheck(o, confdTransCtxRefType);
}

/* ************************************************************************ */
/* struct confd_db_ctx* -> confd._dp.DbCtxRef                               */
/* ************************************************************************ */

static void confdDbCtxRef_dealloc(confdDbCtxRef *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdDbCtxRef_str(confdDbCtxRef *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".dp.DbCtxRef");
}

static PyObject *confdDbCtxRef_repr(confdDbCtxRef *self)
{
    return confdDbCtxRef_str(self);
}

static int confdDbCtxRef_init(confdDbCtxRef *self,
                              PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdDbCtxRef_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.DbCtxRef from Python");

    return NULL;
}

static PyObject *confdDbCtxRef_dx(confdDbCtxRef *self)
{
    return (PyObject*)PyConfd_DaemonCtxRef_New_NoAutoFree(self->dbx->dx);
}

static PyObject *confdDbCtxRef_lastop(confdDbCtxRef *self)
{
    return PyInt_FromLong(self->dbx->lastop);
}

static PyObject *confdDbCtxRef_did(confdDbCtxRef *self)
{
    return PyInt_FromLong(self->dbx->did);
}

static PyObject *confdDbCtxRef_qref(confdDbCtxRef *self)
{
    return PyInt_FromLong(self->dbx->qref);
}

static PyObject *confdDbCtxRef_uinfo(confdDbCtxRef *self)
{
    return newConfdUserInfo(self->dbx->uinfo);
}

static PyMethodDef confdDbCtxRef_methods[] = {
    MTH_DEF(confdDbCtxRef, dx, METH_NOARGS),
    MTH_DEF(confdDbCtxRef, lastop, METH_NOARGS),
    MTH_DEF(confdDbCtxRef, did, METH_NOARGS),
    MTH_DEF(confdDbCtxRef, qref, METH_NOARGS),
    MTH_DEF(confdDbCtxRef, uinfo, METH_NOARGS),
    {NULL}  /* Sentinel */
};

static int setup_type_confd_dbctxref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdDbCtxRef_new },
        { .slot = Py_tp_init,        .pfunc = confdDbCtxRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdDbCtxRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdDbCtxRef_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdDbCtxRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdDbCtxRef_repr },
        { .slot = Py_tp_str,         .pfunc = confdDbCtxRef_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.DbCtxRef",
        .basicsize = sizeof(confdDbCtxRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdDbCtxRefType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdDbCtxRef(struct confd_db_ctx *dbx)
{
    confdDbCtxRef *self = (confdDbCtxRef*)
        PyObject_New(confdDbCtxRef, confdDbCtxRefType);

    self->dbx = dbx;

    return (PyObject *) self;
}

int isConfdDbCtxRef(PyObject *o)
{
    return PyObject_TypeCheck(o, confdDbCtxRefType);
}

/* ************************************************************************ */
/* struct confd_trans_ctx* -> confd.UserInfo                           */
/* ************************************************************************ */


static void confdUserInfo_dealloc(confdUserInfo *self)
{
    Py_XDECREF(self->username);
    Py_XDECREF(self->context);
    Py_XDECREF(self->addr);
    Py_XDECREF(self->snmp_v3_ctx);
    Py_XDECREF(self->clearpass);
    Py_XDECREF(self->logintime);

    if (self->free_uinfo) {
        free(self->uinfo);
    }

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdUserInfo_str(confdUserInfo *self)
{
    return PyString_FromString(CONFD_PY_MODULE ".UserInfo");
}


static PyObject *confdUserInfo_repr(confdUserInfo *self)
{
    return confdUserInfo_str(self);
}

static int confdUserInfo_init(confdUserInfo *self,
                                 PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdUserInfo_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".UserInfo from Python");

    return NULL;
}


static PyMemberDef confdUserInfo_members[] = {
    {"username", T_OBJECT_EX, offsetof(confdUserInfo, username), 0,
     confdUserInfo_attr_username__doc__},
    {"usid", T_INT, offsetof(confdUserInfo, usid), 0,
     confdUserInfo_attr_usid__doc__},
    {"context", T_OBJECT_EX, offsetof(confdUserInfo, context), 0,
     confdUserInfo_attr_context__doc__},
    {"af", T_INT, offsetof(confdUserInfo, af), 0,
     confdUserInfo_attr_af__doc__},
    {"addr", T_OBJECT_EX, offsetof(confdUserInfo, addr), 0,
     confdUserInfo_attr_addr__doc__},
    {"snmp_v3_ctx", T_OBJECT_EX, offsetof(confdUserInfo, snmp_v3_ctx), 0,
     confdUserInfo_attr_snmp_v3_ctx__doc__},
    {"clearpass", T_OBJECT_EX, offsetof(confdUserInfo, clearpass), 0,
     confdUserInfo_attr_clearpass__doc__},
    {"logintime", T_OBJECT_EX, offsetof(confdUserInfo, logintime), 0,
     confdUserInfo_attr_logintime__doc__},
    {"proto", T_INT, offsetof(confdUserInfo, proto), 0,
     confdUserInfo_attr_proto__doc__},
    {"port", T_INT, offsetof(confdUserInfo, port), 0,
     confdUserInfo_attr_port__doc__},
    {"lmode", T_INT, offsetof(confdUserInfo, lmode), 0,
     confdUserInfo_attr_lmode__doc__},
    {"flags", T_INT, offsetof(confdUserInfo, flags), 0,
     confdUserInfo_attr_flags__doc__},
    {"actx_thandle", T_INT, offsetof(confdUserInfo, actx_thandle), 0,
     confdUserInfo_attr_actx_thandle__doc__},

    {NULL}  /* Sentinel */
};

static PyMethodDef confdUserInfo_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_userinfo(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdUserInfo_new },
        { .slot = Py_tp_init,        .pfunc = confdUserInfo_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdUserInfo_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdUserInfo_methods },
        { .slot = Py_tp_members,     .pfunc = confdUserInfo_members },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdUserInfo__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdUserInfo_repr },
        { .slot = Py_tp_str,         .pfunc = confdUserInfo_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".UserInfo",
        .basicsize = sizeof(confdUserInfo),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdUserInfoType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdUserInfo(struct confd_user_info *ui)
{
    confdUserInfo *self = (confdUserInfo*)
        PyObject_New(confdUserInfo, confdUserInfoType);

    self->uinfo = ui;
    self->username = PyString_FromString(ui->username);
    self->usid = ui->usid;
    self->context = PyString_FromString(ui->context);
    self->af = ui->af;
    self->snmp_v3_ctx = PyString_FromString(ui->snmp_v3_ctx);
    self->clearpass = PyString_FromString(ui->clearpass);
    self->logintime = PyLong_FromLong((long) ui->logintime);

    if (ui->af == AF_INET) {
        char str[INET_ADDRSTRLEN];
        self->addr = PyString_FromString(
                inet_ntop(AF_INET, &ui->ip.v4, str, sizeof(str)));
    } else if (ui->af == AF_INET6) {
        char str[INET6_ADDRSTRLEN];
        self->addr = PyString_FromString(
                inet_ntop(AF_INET6, &ui->ip.v6, str, sizeof(str)));
     } else {
        self->addr = PyString_FromString("Unknown address type");
    }

    self->proto = ui->proto;
    self->port = ui->port;
    self->lmode = ui->lmode;
    self->flags = ui->flags;
    self->actx_thandle = ui->actx.thandle;

    self->free_uinfo = 0;

    return (PyObject *) self;
}

PyObject* newConfdUserInfoFree(struct confd_user_info *ui)
{
    confdUserInfo *self = (confdUserInfo*)newConfdUserInfo(ui);
    self->free_uinfo = 1;
    return (PyObject*)self;
}

int isConfdUserInfo(PyObject *o)
{
    return PyObject_TypeCheck(o, confdUserInfoType);
}


/* ************************************************************************ */
/* struct confd_authorizationInfo -> confd.AuthorizationInfo           */
/* ************************************************************************ */


static void confdAuthorizationInfo_dealloc(confdAuthorizationInfo *self)
{
    Py_XDECREF(self->groups);

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdAuthorizationInfo_str(confdAuthorizationInfo *self)
{
    return PyString_FromString(CONFD_PY_MODULE ".AuthorizationInfo");
}


static PyObject *confdAuthorizationInfo_repr(confdAuthorizationInfo *self)
{
    return confdAuthorizationInfo_str(self);
}

static int confdAuthorizationInfo_init(confdAuthorizationInfo *self,
                                 PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdAuthorizationInfo_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".AuthorizationInfo from Python");

    return NULL;
}

static PyMemberDef confdAuthorizationInfo_members[] = {
    {"groups", T_OBJECT_EX, offsetof(confdAuthorizationInfo, groups), 0,
     confdAuthorizationInfo_attr_groups__doc__},
    {NULL}  /* Sentinel */
};

static PyMethodDef confdAuthorizationInfo_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_authorizationinfo(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdAuthorizationInfo_new },
        { .slot = Py_tp_init,        .pfunc = confdAuthorizationInfo_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdAuthorizationInfo_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdAuthorizationInfo_methods },
        { .slot = Py_tp_members,     .pfunc = confdAuthorizationInfo_members },
        { .slot = Py_tp_doc,    .pfunc = (void*)confdAuthorizationInfo__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdAuthorizationInfo_repr },
        { .slot = Py_tp_str,         .pfunc = confdAuthorizationInfo_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".AuthorizationInfo",
        .basicsize = sizeof(confdAuthorizationInfo),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdAuthorizationInfoType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdAuthorizationInfoType == NULL)
        return -1;
    return 0;
}

PyObject* newConfdAuthorizationInfo(struct confd_authorization_info *ai)
{
    PyObject *pys;
    PyObject *groups = PyTuple_New(ai->ngroups);
    int c;

    if (groups == NULL) {
        return NULL;
    }

    confdAuthorizationInfo *self = (confdAuthorizationInfo*)
        PyObject_New(confdAuthorizationInfo, confdAuthorizationInfoType);

    pys = (PyObject *) self;

    for (c = 0; c < ai->ngroups; c++) {
        PyTuple_SetItem(groups, c, PyString_FromString(ai->groups[c]));
    }

    self->groups = groups;

    return pys;
}

int isConfdAuthorizationInfo(PyObject *o)
{
    return PyObject_TypeCheck(o, confdAuthorizationInfoType);
}

/* ************************************************************************ */
/* struct confd_auth_ctx -> confd._dp.AuthCtxRef                            */
/* ************************************************************************ */
static void authCtxRef_dealloc(confdAuthCtxRef *self)
{
    Py_XDECREF(self->groups);
    Py_XDECREF(self->logno);
    Py_XDECREF(self->reason);

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *authCtxRef_str(confdAuthCtxRef *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".dp.AuthCtxRef");
}

static PyObject *authCtxRef_repr(confdAuthCtxRef *self)
{
    return authCtxRef_str(self);
}

static int authCtxRef_init(
        confdAuthCtxRef *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *authCtxRef_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.AuthCtxRef from Python");

    return NULL;
}

static PyMethodDef authCtxRef_methods[] = {
    {NULL}  /* Sentinel */
};


static PyObject *authCtxRef_getattro_c_str(confdAuthCtxRef *self,
                                           PyObject *name_,
                                           const char *name)
{
    if (strcmp(name, "uinfo") == 0) {
        if (self->actx->uinfo != NULL) {
            return newConfdUserInfo(self->actx->uinfo);
        } else {
            Py_RETURN_NONE;
        }
    }
    if (strcmp(name, "method") == 0) {
        return PyString_FromString(self->actx->method);
    }
    if (strcmp(name, "success") == 0) {
        return PyBool_FromLong(self->actx->success);
    }
    if (strcmp(name, "groups") == 0) {
        if (self->groups != NULL) {
            Py_INCREF(self->groups);
            return self->groups;
        } else {
            Py_RETURN_NONE;
        }
    }
    if (strcmp(name, "logno") == 0) {
        if (self->logno != NULL) {
            Py_INCREF(self->logno);
            return self->logno;
        } else {
            Py_RETURN_NONE;
        }
    }
    if (strcmp(name, "reason") == 0) {
        if (self->reason != NULL) {
            Py_INCREF(self->reason);
            return self->reason;
        } else {
            Py_RETURN_NONE;
        }
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyObject *authCtxRef_getattro(
        confdAuthCtxRef *self, PyObject *name_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    PyObject *res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = authCtxRef_getattro_c_str(self, name_, name);
    }
    return res;
}

static int setup_type_confd_authctxref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = authCtxRef_new },
        { .slot = Py_tp_init,        .pfunc = authCtxRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = authCtxRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = authCtxRef_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdAuthCtxRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = authCtxRef_repr },
        { .slot = Py_tp_str,         .pfunc = authCtxRef_str },
        { .slot = Py_tp_getattro,    .pfunc = authCtxRef_getattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.AuthCtxRef",
        .basicsize = sizeof(confdAuthCtxRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdAuthCtxRefType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdAuthCtxRefType == NULL)
        return -1;
    return 0;
}

PyObject *newConfdAuthCtxRef(
        struct confd_auth_ctx *ctx)
{
    confdAuthCtxRef *self =
        (confdAuthCtxRef *)
            PyObject_New(confdAuthCtxRef, confdAuthCtxRefType);

    if (self != NULL) {
        self->actx = ctx;
        self->groups = NULL;
        self->logno = NULL;
        self->reason = NULL;
    }

    if (self->actx->success != 0) {
        int n = self->actx->ainfo.succ.ngroups;
        char **g = self->actx->ainfo.succ.groups;
        self->groups = PyTuple_New(n);
        int i;
        for (i = 0; i < n; i++) {
            PyTuple_SetItem(self->groups, i, PyString_FromString(g[i]));
        }
    } else {
        self->logno = PyInt_FromLong(self->actx->ainfo.fail.logno);
        self->reason = PyString_FromString(self->actx->ainfo.fail.reason);
    }

    return (PyObject*)self;
}

int isConfdAuthCtxRef(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdAuthCtxRefType);
}

/* ************************************************************************ */
/* struct confd_authorization_ctx -> confd._dp.AuthorizationCtxRef          */
/* ************************************************************************ */
static void authorizationCtxRef_dealloc(confdAuthorizationCtxRef *self)
{
    Py_XDECREF(self->uinfo);
    Py_XDECREF(self->groups);

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *authorizationCtxRef_str(confdAuthorizationCtxRef *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".dp.AuthorizationCtxRef");
}

static PyObject *authorizationCtxRef_repr(confdAuthorizationCtxRef *self)
{
    return authorizationCtxRef_str(self);
}

static int authorizationCtxRef_init(
        confdAuthorizationCtxRef *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *authorizationCtxRef_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.AuthorizationCtxRef from Python");

    return NULL;
}

static PyMethodDef authorizationCtxRef_methods[] = {
    {NULL}  /* Sentinel */
};

static PyObject *authorizationCtxRef_getattro_c_str(
                                                confdAuthorizationCtxRef *self,
                                                    PyObject *name_,
                                                    const char *name)
{
    if (strcmp(name, "uinfo") == 0) {
        if (self->uinfo != NULL) {
            Py_INCREF(self->uinfo);
            return self->uinfo;
        }
        else {
            Py_RETURN_NONE;
        }
    }
    if (strcmp(name, "groups") == 0) {
        if (self->groups != NULL) {
            Py_INCREF(self->groups);
            return self->groups;
        }
        else {
            Py_RETURN_NONE;
        }
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyObject *authorizationCtxRef_getattro(
        confdAuthorizationCtxRef *self, PyObject *name_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    PyObject *res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = authorizationCtxRef_getattro_c_str(self, name_, name);
    }
    return res;
}

static int setup_type_confd_authorizationctxref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = authorizationCtxRef_new },
        { .slot = Py_tp_init,        .pfunc = authorizationCtxRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = authorizationCtxRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = authorizationCtxRef_methods },
        { .slot = Py_tp_doc,  .pfunc = (void*)confdAuthorizationCtxRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = authorizationCtxRef_repr },
        { .slot = Py_tp_str,         .pfunc = authorizationCtxRef_str },
        { .slot = Py_tp_getattro,    .pfunc = authorizationCtxRef_getattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.AuthorizationCtxRef",
        .basicsize = sizeof(confdAuthorizationCtxRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdAuthorizationCtxRefType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdAuthorizationCtxRefType == NULL)
        return -1;
    return 0;
}

PyObject *newConfdAuthorizationCtxRef(
        struct confd_authorization_ctx *ctx)
{
    confdAuthorizationCtxRef *self =
        (confdAuthorizationCtxRef *)
            PyObject_New(confdAuthorizationCtxRef,
                         confdAuthorizationCtxRefType);

    if (self != NULL) {
        self->actx = ctx;
        self->uinfo = NULL;
        self->groups = NULL;
    }

    if (self->actx->uinfo != NULL) {
        self->uinfo = newConfdUserInfo(self->actx->uinfo);
    }
    if (self->actx->ngroups > 0 && self->actx->groups != NULL) {
        self->groups = PyTuple_New(self->actx->ngroups);
        int i;
        for (i = 0; i < self->actx->ngroups; i++) {
            PyTuple_SetItem(self->groups, i,
                            PyString_FromString(self->actx->groups[i]));
        }
    }

    return (PyObject*)self;
}

int isConfdAuthorizationCtxRef(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdAuthorizationCtxRefType);
}

/* ************************************************************************ */
/* struct confd_notification_ctx -> confd._dp.NotificationCtxRef            */
/* ************************************************************************ */

static void notificationCtxRef_dealloc(confdNotificationCtxRef *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *notificationCtxRef_str(confdNotificationCtxRef *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".dp.NotificationCtxRef");
}

static PyObject *notificationCtxRef_repr(confdNotificationCtxRef *self)
{
    return notificationCtxRef_str(self);
}

static PyObject *notificationCtxRef_getattro_c_str(
                                               confdNotificationCtxRef *self,
                                                   PyObject *name_,
                                                   const char *name)
{
    if (strcmp(name, "name") == 0) {
        if (self->nctx->name != NULL) {
            return PyString_FromString(self->nctx->name);
        }
        else {
            Py_RETURN_NONE;
        }
    }
    if (strcmp(name, "ctx_name") == 0) {
        if (self->nctx->ctx_name != NULL) {
            return PyString_FromString(self->nctx->ctx_name);
        }
        else {
            Py_RETURN_NONE;
        }
    }
    if (strcmp(name, "fd") == 0) {
        return PyInt_FromLong(self->nctx->fd);
    }
    if (strcmp(name, "dx") == 0) {
        return (PyObject*)PyConfd_DaemonCtxRef_New_NoAutoFree(self->nctx->dx);
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyObject *notificationCtxRef_getattro(
        confdNotificationCtxRef *self, PyObject *name_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    PyObject *res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = notificationCtxRef_getattro_c_str(self, name_, name);
    }
    return res;
}

static int notificationCtxRef_init(
        confdNotificationCtxRef *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *notificationCtxRef_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.NotificationCtxRef from Python");

    return NULL;
}

static PyMethodDef notificationCtxRef_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_notificationctxref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = notificationCtxRef_new },
        { .slot = Py_tp_init,        .pfunc = notificationCtxRef_init },
        { .slot = Py_tp_dealloc,     .pfunc = notificationCtxRef_dealloc },
        { .slot = Py_tp_methods,     .pfunc = notificationCtxRef_methods },
        { .slot = Py_tp_doc,   .pfunc = (void*)confdNotificationCtxRef__doc__ },
        { .slot = Py_tp_repr,        .pfunc = notificationCtxRef_repr },
        { .slot = Py_tp_str,         .pfunc = notificationCtxRef_str },
        { .slot = Py_tp_getattro,    .pfunc = notificationCtxRef_getattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.NotificationCtxRef",
        .basicsize = sizeof(confdNotificationCtxRef),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdNotificationCtxRefType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdNotificationCtxRefType == NULL)
        return -1;
    return 0;
}

PyObject *newConfdNotificationCtxRef(
        struct confd_notification_ctx *ctx)
{
    confdNotificationCtxRef *self =
        (confdNotificationCtxRef *)
            PyObject_New(confdNotificationCtxRef,
                         confdNotificationCtxRefType);

    if (self != NULL) {
        self->nctx = ctx;
    }

    return (PyObject*)self;
}

int isConfdNotificationCtxRef(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdNotificationCtxRefType);
}

/* ************************************************************************ */
/* struct confd_notifications_data -> confd._events.NotificationsData       */
/* ************************************************************************ */

static void confdNotificationsData_dealloc(confdNotificationsData *self)
{
    if (self->nd.stream_name) {
        free(self->nd.stream_name);
    }
    if (self->nd.xpath_filter) {
        free(self->nd.xpath_filter);
    }

    confd_free_value(&self->nd.start_time);
    confd_free_value(&self->nd.stop_time);

    PY_TP_FREE(self);
}

static PyObject *confdNotificationsData_str(confdNotificationsData *self)
{
    PyConfd_Value_Object *start_time =
      PyConfd_Value_New_DupTo(&self->nd.start_time);
    PyConfd_Value_Object *stop_time =
      PyConfd_Value_New_DupTo(&self->nd.stop_time);

    PyObject *res;
    CONFD_PY_WITH_C_STR(confdValue_str(start_time), start_time_c_str) {
        CONFD_PY_WITH_C_STR(confdValue_str(stop_time), stop_time_c_str) {
            res = PyString_FromFormat(
                                  CONFD_PY_MODULE ".events.NotificationsData("
                                      "heartbeat_interval=%d, "
                                      "health_check_interval=%d, "
                                      "stream_name='%s', "
                                      "start_time=%s, "
                                      "stop_time=%s, "
                                      "xpath_filter='%s', "
                                      "usid=%d, "
                                      "verbosity=%d)",
                                      self->nd.heartbeat_interval,
                                      self->nd.health_check_interval,
                                      self->nd.stream_name,
                                      start_time_c_str,
                                      stop_time_c_str,
                                      self->nd.xpath_filter
                                      ? self->nd.xpath_filter : "",
                                  self->nd.usid,
                                  self->nd.verbosity);
        }
    }

    Py_DECREF(start_time);
    Py_DECREF(stop_time);

    return res;
}

static PyObject *confdNotificationsData_repr(confdNotificationsData *self)
{
    return confdNotificationsData_str(self);
}

static int confdNotificationsData_init(
        confdNotificationsData *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "heartbeat_interval",
        "health_check_interval",
        "stream_name",
        "start_time",
        "stop_time",
        "xpath_filter",
        "usid",
        "verbosity",
        NULL
    };

    char *stream_name;
    char *xpath_filter = NULL;
    PyConfd_Value_Object *start_time;
    PyConfd_Value_Object *stop_time;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iisO!O!|sii", kwlist,
                &self->nd.heartbeat_interval,
                &self->nd.health_check_interval,
                &stream_name,
                confdValueType, &start_time,
                confdValueType, &stop_time,
                &xpath_filter,
                &self->nd.usid,
                &self->nd.verbosity)) {
        return -1;
    }

    if (! (start_time->ob_val.type == C_NOEXISTS) ||
          (start_time->ob_val.type == C_DATETIME)) {
        PyErr_Format(PyExc_TypeError, "start_time argument must be of type "
                                      "C_NOEXISTS or C_DATETIME");
        return -1;
    }

    if (! (stop_time->ob_val.type == C_NOEXISTS) ||
          (stop_time->ob_val.type == C_DATETIME)) {
        PyErr_Format(PyExc_TypeError, "stop_time argument must be of type "
                                      "C_NOEXISTS or C_DATETIME");
        return -1;
    }

    if (self->nd.stream_name) {
        free(self->nd.stream_name);
    }
    self->nd.stream_name = strdup(stream_name);

    if (self->nd.xpath_filter) {
        free(self->nd.xpath_filter);
        self->nd.xpath_filter = NULL;
    }
    if (xpath_filter) {
        self->nd.xpath_filter = strdup(xpath_filter);
    }

    confd_free_value(&self->nd.start_time);
    confd_value_dup_to(PyConfd_Value_PTR(start_time), &self->nd.start_time);

    confd_free_value(&self->nd.stop_time);
    confd_value_dup_to(PyConfd_Value_PTR(stop_time), &self->nd.stop_time);

    return 0;
}

static PyObject *confdNotificationsData_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    confdNotificationsData *self = (confdNotificationsData *)PY_TP_ALLOC(type);

    if (self == NULL) {
        PyErr_Format(PyExc_Exception, "Failed to create a "
                     CONFD_PY_MODULE ".events.NotificationsData instance");
        return NULL;
    }

    memset(&self->nd, 0, sizeof(struct confd_notifications_data));

    return (PyObject*)self;
}


static PyMemberDef confdNotificationsData_members[] = {

    {NULL}  /* Sentinel */
};

static int setup_type_confd_notificationsdata(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdNotificationsData_new },
        { .slot = Py_tp_init,        .pfunc = confdNotificationsData_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdNotificationsData_dealloc },
        { .slot = Py_tp_members,     .pfunc = confdNotificationsData_members },
        { .slot = Py_tp_doc,    .pfunc = (void*)confdNotificationsData__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdNotificationsData_repr },
        { .slot = Py_tp_str,         .pfunc = confdNotificationsData_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".events.NotificationsData",
        .basicsize = sizeof(confdNotificationsData),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdNotificationsDataType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdNotificationsDataType == NULL)
        return -1;
    return 0;
}

int isConfdNotificationsData(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdNotificationsDataType);
}

/* ************************************************************************ */
/* struct confd_notification -> confd._events.NotificationRef               */
/* ************************************************************************ */
static const char *notif_type2str(int type)
{
    switch (type) {
        case CONFD_NOTIF_AUDIT:
            return "CONFD_NOTIF_AUDIT";
        case CONFD_NOTIF_DAEMON:
            return "CONFD_NOTIF_DAEMON";
        case CONFD_NOTIF_TAKEOVER_SYSLOG:
            return "CONFD_NOTIF_TAKEOVER_SYSLOG";
        case CONFD_NOTIF_COMMIT_SIMPLE:
            return "CONFD_NOTIF_COMMIT_SIMPLE";
        case CONFD_NOTIF_COMMIT_DIFF:
            return "CONFD_NOTIF_COMMIT_DIFF";
        case CONFD_NOTIF_USER_SESSION:
            return "CONFD_NOTIF_USER_SESSION";
        case CONFD_NOTIF_HA_INFO:
            return "CONFD_NOTIF_HA_INFO";
        case CONFD_NOTIF_SUBAGENT_INFO:
            return "CONFD_NOTIF_SUBAGENT_INFO";
        case CONFD_NOTIF_COMMIT_FAILED:
            return "CONFD_NOTIF_COMMIT_FAILED";
        case CONFD_NOTIF_SNMPA:
            return "CONFD_NOTIF_SNMPA";
        case CONFD_NOTIF_FORWARD_INFO:
            return "CONFD_NOTIF_FORWARD_INFO";
        case CONFD_NOTIF_NETCONF:
            return "CONFD_NOTIF_NETCONF";
        case CONFD_NOTIF_DEVEL:
            return "CONFD_NOTIF_DEVEL";
        case CONFD_NOTIF_HEARTBEAT:
            return "CONFD_NOTIF_HEARTBEAT";
        case CONFD_NOTIF_CONFIRMED_COMMIT:
            return "CONFD_NOTIF_CONFIRMED_COMMIT";
        case CONFD_NOTIF_UPGRADE_EVENT:
            return "CONFD_NOTIF_UPGRADE_EVENT";
        case CONFD_NOTIF_COMMIT_PROGRESS:
            return "CONFD_NOTIF_COMMIT_PROGRESS";
        case CONFD_NOTIF_PROGRESS:
            return "CONFD_NOTIF_PROGRESS";
        case CONFD_NOTIF_AUDIT_SYNC:
            return "CONFD_NOTIF_AUDIT_SYNC";
        case CONFD_NOTIF_HEALTH_CHECK:
            return "CONFD_NOTIF_HEALTH_CHECK";
        case CONFD_NOTIF_STREAM_EVENT:
            return "CONFD_NOTIF_STREAM_EVENT";
        case CONFD_NOTIF_HA_INFO_SYNC:
            return "CONFD_NOTIF_HA_INFO_SYNC";
        case NCS_NOTIF_PACKAGE_RELOAD:
            return "NCS_NOTIF_PACKAGE_RELOAD";
        case NCS_NOTIF_CQ_PROGRESS:
            return "NCS_NOTIF_CQ_PROGRESS";
        case CONFD_NOTIF_REOPEN_LOGS:
            return "CONFD_NOTIF_REOPEN_LOGS";
        case NCS_NOTIF_CALL_HOME_INFO:
            return "NCS_NOTIF_CALL_HOME_INFO";
        case CONFD_NOTIF_JSONRPC:
            return "CONFD_NOTIF_JSONRPC";
        case CONFD_NOTIF_WEBUI:
            return "CONFD_NOTIF_WEBUI";
        case NCS_NOTIF_AUDIT_NETWORK:
            return "NCS_NOTIF_AUDIT_NETWORK";
        case NCS_NOTIF_AUDIT_NETWORK_SYNC:
            return "NCS_NOTIF_AUDIT_NETWORK_SYNC";
        default:
            return "unknown notification type";
    }
}

static void confdNotification_dealloc(confdNotification *self)
{
    PY_TP_FREE(self);
}

static PyObject *confdNotification_str(confdNotification *self)
{
    PyObject *res = PyString_FromFormat(
            CONFD_PY_MODULE ".events.Notification(type=%s (%d))",
            notif_type2str(self->n.type), self->n.type);
    return res;
}

static PyObject *confdNotification_repr(confdNotification *self)
{
    return confdNotification_str(self);
}

static PyObject *confdNotification_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".events.Notification from Python");

    return NULL;
}

static int setup_type_confd_notification(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdNotification_new },
        { .slot = Py_tp_dealloc,     .pfunc = confdNotification_dealloc },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdNotification__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdNotification_repr },
        { .slot = Py_tp_str,         .pfunc = confdNotification_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".events.Notification",
        .basicsize = sizeof(confdNotification),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdNotificationType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdNotificationType == NULL)
        return -1;
    return 0;
}

confdNotification *newConfdNotification()
{
    confdNotification *self =
        (confdNotification*)PyObject_New(confdNotification,
                                         confdNotificationType);

    if (self != NULL) {
        memset(&self->n, 0, sizeof(struct confd_notification));
    }

    return self;
}

/* ************************************************************************ */
/* struct confd_datetime -> confd.DateTime                             */
/* ************************************************************************ */
static void confdDateTime_dealloc(confdDateTime *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdDateTime_str(confdDateTime *self)
{
    return PyString_FromFormat(
            CONFD_PY_MODULE ".DateTime("
            "year=%d, month=%d, day=%d, "
            "hour=%d, min=%d, sec=%d, micro=%d, "
            "timezone=%d, timezone_minutes=%d)",
            self->dt.year,
            self->dt.month,
            self->dt.day,
            self->dt.hour,
            self->dt.min,
            self->dt.sec,
            self->dt.micro,
            self->dt.timezone,
            self->dt.timezone_minutes);
}

static PyObject *confdDateTime_repr(confdDateTime *self)
{
    return confdDateTime_str(self);
}

static int confdDateTime_init(
        confdDateTime *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *confdDateTime_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "year",
        "month",
        "day",
        "hour",
        "min",
        "sec",
        "micro",
        "timezone",
        "timezone_minutes",
        NULL
    };

    struct confd_datetime dt;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "hbbbbbIBB", kwlist,
                &dt.year, &dt.month, &dt.day,
                &dt.hour, &dt.min, &dt.sec, &dt.micro,
                &dt.timezone, &dt.timezone_minutes)) {
        return NULL;
    }

    return newConfdDateTime(&dt);
}

static PyMethodDef confdDateTime_methods[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef confdDateTime_members[] = {
    {"year", T_SHORT, offsetof(confdDateTime, dt.year), 0,
     confdDateTime_attr_year__doc__},
    {"month", T_UBYTE, offsetof(confdDateTime, dt.month), 0,
     confdDateTime_attr_month__doc__},
    {"day", T_UBYTE, offsetof(confdDateTime, dt.day), 0,
     confdDateTime_attr_day__doc__},
    {"hour", T_UBYTE, offsetof(confdDateTime, dt.hour), 0,
     confdDateTime_attr_hour__doc__},
    {"min", T_UBYTE, offsetof(confdDateTime, dt.min), 0,
     confdDateTime_attr_min__doc__},
    {"sec", T_UBYTE, offsetof(confdDateTime, dt.sec), 0,
     confdDateTime_attr_sec__doc__},
    {"micro", T_UINT, offsetof(confdDateTime, dt.micro), 0,
     confdDateTime_attr_micro__doc__},
    {"timezone", T_BYTE, offsetof(confdDateTime, dt.timezone), 0,
     confdDateTime_attr_timezone__doc__},
    {"timezone_minutes", T_BYTE,
        offsetof(confdDateTime, dt.timezone_minutes), 0,
        confdDateTime_attr_timezone_minutes__doc__},

    {NULL}  /* Sentinel */
};

static int setup_type_confd_datetime(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdDateTime_new },
        { .slot = Py_tp_init,        .pfunc = confdDateTime_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdDateTime_dealloc },
        { .slot = Py_tp_members,     .pfunc = confdDateTime_members },
        { .slot = Py_tp_methods,     .pfunc = confdDateTime_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdDateTime__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdDateTime_repr },
        { .slot = Py_tp_str,         .pfunc = confdDateTime_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".DateTime",
        .basicsize = sizeof(confdDateTime),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdDateTimeType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdDateTimeType == NULL)
        return -1;
    return 0;
}

PyObject *newConfdDateTime(struct confd_datetime *dt)
{
    confdDateTime *self =
        (confdDateTime *)
            PyObject_New(confdDateTime, confdDateTimeType);

    if (self != NULL) {
        memcpy(&self->dt, dt, sizeof(struct confd_datetime));
    }

    return (PyObject*)self;
}

int isConfdDateTime(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdDateTimeType);
}

/* ************************************************************************ */
/* struct confd_snmp_varbind -> confd.SnmpVarbind                      */
/* ************************************************************************ */

static void confdSnmpVarbind_dealloc(confdSnmpVarbind *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdSnmpVarbind_str(confdSnmpVarbind *self)
{
    return PyString_FromFormat(
            CONFD_PY_MODULE ".SnmpVarbind("
            "type=%d)", self->vb.type);
}

static PyObject *confdSnmpVarbind_repr(confdSnmpVarbind *self)
{
    return confdSnmpVarbind_str(self);
}

static int confdSnmpVarbind_init(
        confdSnmpVarbind *self, PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *confdSnmpVarbind_new(
        PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "type",
        "val",
        "vartype",
        "name",
        "oid",    /* list(int) */
        "cr",     /* tuple(string, list(int)) */
        NULL
    };

    enum confd_snmp_var_type ctype;
    PyConfd_Value_Object *val;
    enum confd_snmp_type vartype = CONFD_SNMP_NULL;
    char *name = NULL;
    PyObject *oid = NULL;
    PyObject *cr = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "iO|isOO", kwlist,
                &ctype, &val, &vartype,
                &name, &oid, &cr)) {
        return NULL;
    }

    if (!PyConfd_Value_CheckExact((PyObject*)val)) {
        PyErr_Format(PyExc_TypeError, "val argument must be a "
                     CONFD_PY_MODULE ".Value instance");
        return NULL;
    }

    struct confd_snmp_varbind vb;
    memset(&vb, 0, sizeof(vb));

    vb.type = ctype;
    vb.vartype = vartype;
    vb.val = val->ob_val;

    if (ctype == CONFD_SNMP_VARIABLE) {
        if (name == NULL) {
            PyErr_Format(PyExc_TypeError, "name argument must be provided");
            return NULL;
        }
        strncpy(vb.var.name, name, sizeof(vb.var.name)-1);
    }
    else if (ctype == CONFD_SNMP_OID) {
        if (oid == NULL ) {
            PyErr_Format(PyExc_TypeError, "oid argument must be provided");
            return NULL;
        }
        if (!PyList_Check(oid)) {
            PyErr_Format(PyExc_TypeError,
                    "oid argument must be a list of integers");
            return NULL;
        }
        Py_ssize_t ls = PyList_Size(oid);
        if (ls < 1 || ls > 128) {
            PyErr_Format(PyExc_TypeError,
                    "oid argument must be a list of at least 1 and up to at "
                    "most 128 integers");
            return NULL;
        }
        vb.var.oid.len = (int)ls;

        int i;
        PyObject *o;
        for (i = 0; i < ls; i++) {
            o = PyList_GetItem(oid, i);
            if (!PyInt_Check(o)) {
                PyErr_Format(PyExc_TypeError,
                        "item %d of oid argument must be an integer", i);
                return NULL;
            }
            vb.var.oid.oid[i] = (u_int32_t)PyInt_AsLong(o);
        }
    }
    else if (ctype == CONFD_SNMP_COL_ROW) {
        if (cr == NULL ) {
            PyErr_Format(PyExc_TypeError, "cr argument must be provided");
            return NULL;
        }
        if (!PyTuple_Check(cr) || PyTuple_Size(cr) != 2) {
            PyErr_Format(PyExc_TypeError,
                    "cr argument must be a 2-tuple");
            return NULL;
        }

        PyObject *to = PyTuple_GetItem(cr, 0);

        if (!PyString_Check(to)) {
            PyErr_Format(PyExc_TypeError,
                    "first argument of cr tuple (column) must be a string");
            return NULL;
        }
        CONFD_PY_WITH_C_STR(to, to_c_str) {
            strncpy(vb.var.cr.column, to_c_str, sizeof(vb.var.cr.column)-1);
        }

        to = PyTuple_GetItem(cr, 1);

        if (!PyList_Check(to)) {
            PyErr_Format(PyExc_TypeError,
                    "second argument of cr (rowindex) must be a "
                    "list of integers");
            return NULL;
        }

        Py_ssize_t ls = PyList_Size(to);

        if (ls < 1 || ls > 128) {
            PyErr_Format(PyExc_TypeError,
                    "second argument of cr (rowindex) must be a list of at "
                    "least 1 and up to at most 128 integers");
            return NULL;
        }

        vb.var.cr.rowindex.len = (int)ls;

        int i;
        PyObject *o;
        for (i = 0; i < ls; i++) {
            o = PyList_GetItem(to, i);
            if (!PyInt_Check(o)) {
                PyErr_Format(PyExc_TypeError,
                        "item %d of second argument of cr (rowindex) "
                        "must be an integer", i);
                return NULL;
            }
            vb.var.cr.rowindex.oid[i] = (u_int32_t)PyInt_AsLong(o);
        }
    }
    else {
        PyErr_Format(PyExc_TypeError,
                "type argument must be one of "
                "SNMP_VARIABLE, SNMP_OID or SNMP_COL_ROW");
        return NULL;
    }

    return newConfdSnmpVarbind(&vb);
}

static PyMethodDef confdSnmpVarbind_methods[] = {
    {NULL}  /* Sentinel */
};

static PyMemberDef confdSnmpVarbind_members[] = {
    {"type", T_INT, offsetof(confdSnmpVarbind, vb.type), READONLY,
      confdSnmpVarbind_attr_type__doc__},
    {NULL}  /* Sentinel */
};

static int setup_type_confd_snmpvarbind(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdSnmpVarbind_new },
        { .slot = Py_tp_init,        .pfunc = confdSnmpVarbind_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdSnmpVarbind_dealloc },
        { .slot = Py_tp_members,     .pfunc = confdSnmpVarbind_members },
        { .slot = Py_tp_methods,     .pfunc = confdSnmpVarbind_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdSnmpVarbind__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdSnmpVarbind_repr },
        { .slot = Py_tp_str,         .pfunc = confdSnmpVarbind_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".SnmpVarbind",
        .basicsize = sizeof(confdSnmpVarbind),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdSnmpVarbindType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdSnmpVarbindType == NULL)
        return -1;
    return 0;
}

PyObject *newConfdSnmpVarbind(struct confd_snmp_varbind *vb)
{
    confdSnmpVarbind *self =
        (confdSnmpVarbind *)
            PyObject_New(confdSnmpVarbind, confdSnmpVarbindType);

    if (self != NULL) {
        memcpy(&self->vb, vb, sizeof(struct confd_snmp_varbind));
        confd_value_dup_to(&vb->val, &self->vb.val);
    }

    return (PyObject*)self;
}

int isConfdSnmpVarbind(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdSnmpVarbindType);
}


/* ************************************************************************ */
/* struct confd_daemon_ctx -> confd._dp.DaemonCtxRef                        */
/* ************************************************************************ */

static void daemonCtx_dealloc(PyConfd_DaemonCtxRef_Object *self)
{

    if (self->ctx != NULL && self->autoFree == 1) {
        PyObject* opaque = NULL;

        /* Normally this is already done by the _dp_release_daemon call,
         * but just to be safe
         */

        opaque = (PyObject *) self->ctx->d_opaque;

        Py_XDECREF(opaque);

        self->ctx = NULL;
    }


    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *daemonCtx_str(PyConfd_DaemonCtxRef_Object *self)
{
    return PyString_FromFormat(
            CONFD_PY_MODULE ".dp.DaemonCtxRef(%s @ %p)",
            self->ctx->name, self->ctx);
}


static PyObject *daemonCtx_repr(PyConfd_DaemonCtxRef_Object *self)
{
    return daemonCtx_str(self);
}

static int daemonCtx_init(PyConfd_DaemonCtxRef_Object *self, PyObject *args,
                PyObject *kwds)
{
    return 0;
}

static PyObject *
daemonCtx_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.DaemonCtxRef from Python");

    return NULL;
}


static PyMethodDef daemonCtx_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_daemonctxref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = daemonCtx_new },
        { .slot = Py_tp_init,        .pfunc = daemonCtx_init },
        { .slot = Py_tp_dealloc,     .pfunc = daemonCtx_dealloc },
        { .slot = Py_tp_methods,     .pfunc = daemonCtx_methods },
        { .slot = Py_tp_doc,         .pfunc =
            "struct confd_daemon_ctx references object" },
        { .slot = Py_tp_repr,        .pfunc = daemonCtx_repr },
        { .slot = Py_tp_str,         .pfunc = daemonCtx_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.DaemonCtxRef",
        .basicsize = sizeof(PyConfd_DaemonCtxRef_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdDaemonCtxRefType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdDaemonCtxRefType == NULL)
        return -1;
    return 0;
}

PyConfd_DaemonCtxRef_Object *PyConfd_DaemonCtxRef_New(
        struct confd_daemon_ctx *ctx)
{
    PyConfd_DaemonCtxRef_Object *self =
        (PyConfd_DaemonCtxRef_Object *)
            PyObject_New(PyConfd_DaemonCtxRef_Object,
                         confdDaemonCtxRefType);

    if (self != NULL) {
        self->ctx = ctx;
        self->autoFree = 1;
    }

    return self;
}

PyConfd_DaemonCtxRef_Object *PyConfd_DaemonCtxRef_New_NoAutoFree(
        struct confd_daemon_ctx *ctx)
{
    PyConfd_DaemonCtxRef_Object *self =
        (PyConfd_DaemonCtxRef_Object *)
            PyObject_New(PyConfd_DaemonCtxRef_Object,
                         confdDaemonCtxRefType);

    if (self != NULL) {
        self->ctx = ctx;
        self->autoFree = 0;
    }

    return self;
}

int PyConfd_DaemonCtxRef_CheckExact(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdDaemonCtxRefType);
}

/* ************************************************************************ */
/* struct maapi_rollback-> confd._maapi.MaapiRollback                       */
/* ************************************************************************ */

static void maapiRollback_dealloc(PyConfd_MaapiRollback_Object *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *maapiRollback_str(PyConfd_MaapiRollback_Object *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".maapi.MaapiRollback");
}


static PyObject *maapiRollback_repr(PyConfd_MaapiRollback_Object *self)
{
    return maapiRollback_str(self);
}

static int maapiRollback_init(PyConfd_MaapiRollback_Object *self,
                PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
maapiRollback_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".maapi.MaapiRollback from Python");

    return NULL;
}

static PyMemberDef maapiRollback_members[] = {
    {"nr", T_INT,
        offsetof(PyConfd_MaapiRollback_Object, rollback.nr),
        READONLY, maapiRollback_attr_nr__doc__},

    {"creator", T_STRING,
        offsetof(PyConfd_MaapiRollback_Object, creator_),
        READONLY, maapiRollback_attr_creator__doc__},

    {"datestr", T_STRING,
        offsetof(PyConfd_MaapiRollback_Object, datestr_),
        READONLY, maapiRollback_attr_datestr__doc__},

    {"via", T_STRING,
        offsetof(PyConfd_MaapiRollback_Object, via_),
        READONLY, maapiRollback_attr_via__doc__},

    {"fixed_nr", T_INT,
        offsetof(PyConfd_MaapiRollback_Object, rollback.fixed_nr),
        READONLY, maapiRollback_attr_fixed_nr__doc__},

    {"label", T_STRING,
        offsetof(PyConfd_MaapiRollback_Object, label_),
        READONLY, maapiRollback_attr_label__doc__},

    {"comment", T_STRING,
        offsetof(PyConfd_MaapiRollback_Object, comment_),
        READONLY, maapiRollback_attr_comment__doc__},


    {NULL}  /* Sentinel */
};


static PyMethodDef maapiRollback_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_maapirollback(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = maapiRollback_new },
        { .slot = Py_tp_init,        .pfunc = maapiRollback_init },
        { .slot = Py_tp_dealloc,     .pfunc = maapiRollback_dealloc },
        { .slot = Py_tp_members,     .pfunc = maapiRollback_members },
        { .slot = Py_tp_methods,     .pfunc = maapiRollback_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)maapiRollback__doc__ },
        { .slot = Py_tp_repr,        .pfunc = maapiRollback_repr },
        { .slot = Py_tp_str,         .pfunc = maapiRollback_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".maapi.MaapiRollback",
        .basicsize = sizeof(PyConfd_MaapiRollback_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdMaapiRollbackType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdMaapiRollbackType == NULL)
        return -1;
    return 0;
}

PyConfd_MaapiRollback_Object *PyConfd_MaapiRollback_New(
        const struct maapi_rollback *rollback)
{
    PyConfd_MaapiRollback_Object *self = (PyConfd_MaapiRollback_Object *)
            PyObject_New(PyConfd_MaapiRollback_Object,
                    confdMaapiRollbackType);

    if (self != NULL) {
        memcpy(&self->rollback, rollback, sizeof(struct maapi_rollback));

        self->creator_ = (char *) &self->rollback.creator;
        self->datestr_ = (char *) &self->rollback.datestr;
        self->via_ = (char *) &self->rollback.via;
        self->label_ = (char *) &self->rollback.label;
        self->comment_ = (char *) &self->rollback.comment;
    }

    return self;
}

int PyConfd_MaapiRollback_CheckExact(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdMaapiRollbackType);
}

/* ************************************************************************ */
/* struct confd_query_result -> confd.QueryResult                      */
/* ************************************************************************ */

static void queryResult_dealloc(PyConfd_QueryResult_Object *self)
{
    if (self->qrs != NULL) {
        maapi_query_free_result(self->qrs);
    }

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *queryResult_str(PyConfd_QueryResult_Object *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".QueryResult");
}


static PyObject *queryResult_repr(PyConfd_QueryResult_Object *self)
{
    return queryResult_str(self);
}

static int queryResult_init(PyConfd_QueryResult_Object *self,
                PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
queryResult_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".QueryResult from Python");

    return NULL;
}

static PyMemberDef queryResult_members[] = {
    {"type", T_INT,
        offsetof(PyConfd_QueryResult_Object, type), READONLY,
        queryResult_attr_type__doc__},

    {"offset", T_INT,
        offsetof(PyConfd_QueryResult_Object, offset), READONLY,
        queryResult_attr_offset__doc__},

    {"nresults", T_INT,
        offsetof(PyConfd_QueryResult_Object, nresults), READONLY,
        queryResult_attr_nresults__doc__},

    {"nelements", T_INT,
        offsetof(PyConfd_QueryResult_Object, nelements), READONLY,
        queryResult_attr_nelements__doc__},

    {NULL}  /* Sentinel */
};


static PyMethodDef queryResult_methods[] = {
    {NULL}  /* Sentinel */
};

static Py_ssize_t
queryResult_length(PyConfd_QueryResult_Object *qrs)
{
    return qrs->nresults;
}

static PyObject *
queryResult_item(PyConfd_QueryResult_Object *qrs, Py_ssize_t i)
{
    if (i < 0 || i >= qrs->nresults) {
        PyErr_Format(PyExc_IndexError, "index out of range");
        return NULL;
    }


    PyObject *ret = PyList_New(qrs->nelements);
    if (ret == NULL) {
        return NULL;
    }

    int c;
    int rix = (int) i;

    confd_hkeypath_t *hkp;

    for (c = 0; c < qrs->nelements; c++) {
        PyObject *item = NULL;

        switch (qrs->type) {
            case  CONFD_QUERY_STRING :
                item = PyString_FromString(qrs->qrs->results[rix].str[c]);
                break;

            case  CONFD_QUERY_HKEYPATH :
                hkp = &(qrs->qrs->results[rix].hkp[c]);
                item = _confd_hkeypath2PyString(hkp, hkp->len);
                break;

            case  CONFD_QUERY_HKEYPATH_VALUE :
            {
                PyObject *pyhkp = NULL;
                PyObject *pyval = NULL;

                if ((item = PyDict_New()) == NULL) {
                    Py_XDECREF(pyval);
                    Py_XDECREF(pyhkp);
                    Py_XDECREF(item);
                    return NULL;
                }

                hkp = &(qrs->qrs->results[rix].kv[c].hkp);
                pyhkp = _confd_hkeypath2PyString(hkp, hkp->len);

                pyval = (PyObject*)PyConfd_Value_New_DupTo(
                                       &(qrs->qrs->results[rix].kv[c].val));
                if (pyval == NULL) {
                    Py_XDECREF(pyval);
                    Py_XDECREF(pyhkp);
                    Py_XDECREF(item);
                    return NULL;
                }

                PyDict_SetItemString(item, "hkp", pyhkp);
                PyDict_SetItemString(item, "val", pyval);

                Py_XDECREF(pyval);
                Py_XDECREF(pyhkp);

                break;
            }

            case  CONFD_QUERY_TAG_VALUE:
                item = PyConfd_TagValue_New(
                        &(qrs->qrs->results[rix].tv[c]));
                break;


            default :
                PyErr_Format(PyExc_TypeError,
                    "Unsupported query type %d", qrs->type);
                Py_XDECREF(ret);
                return NULL;
        }

        if (item == NULL) {
            Py_XDECREF(ret);
            return NULL;
        } else {
            PyList_SetItem(ret, c, item);
        }
    }

    return ret;
}

static int setup_type_confd_queryresult(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = queryResult_new },
        { .slot = Py_tp_init,        .pfunc = queryResult_init },
        { .slot = Py_tp_dealloc,     .pfunc = queryResult_dealloc },
        { .slot = Py_tp_methods,     .pfunc = queryResult_methods },
        { .slot = Py_tp_members,     .pfunc = queryResult_members },
        { .slot = Py_tp_doc,         .pfunc = (void*)queryResult__doc__ },
        { .slot = Py_tp_repr,        .pfunc = queryResult_repr },
        { .slot = Py_tp_str,         .pfunc = queryResult_str },
        { .slot = Py_sq_length,      .pfunc = queryResult_length },
        { .slot = Py_sq_item,        .pfunc = queryResult_item },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".QueryResult",
        .basicsize = sizeof(PyConfd_QueryResult_Object),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdQueryResultType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdQueryResultType == NULL)
        return -1;
    return 0;
}

PyConfd_QueryResult_Object *PyConfd_QueryResult_New(
        struct confd_query_result *qrs)
{
    PyConfd_QueryResult_Object *self = (PyConfd_QueryResult_Object *)
            PyObject_New(PyConfd_QueryResult_Object, confdQueryResultType);

    if (self != NULL) {
        self->qrs = qrs;

        self->type = qrs->type;
        self->offset = qrs->offset;
        self->nresults = qrs->nresults;
        self->nelements = qrs->nelements;
    }

    return self;
}

int PyConfd_QueryResult_CheckExact(PyObject *o)
{
    return (o != NULL) && (o->ob_type == confdQueryResultType);
}

/* ************************************************************************ */
/* confd_cs_node -> confd.CsNode                                       */
/* ************************************************************************ */

static void confdCsNode_dealloc(confdCsNode *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdCsNode_str(confdCsNode *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".CsNode");
}


static PyObject *confdCsNode_repr(confdCsNode *self)
{
    return confdCsNode_str(self);
}

static int confdCsNode_init(confdCsNode *self,
                              PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdCsNode_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_TypeError,
            "Can't instantiate "
            CONFD_PY_MODULE ".CsNode from Python");

    return NULL;
}

static PyObject *confdCsNode_ns(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;
    return PyInt_FromLong(c->node->ns);
}

static PyObject *confdCsNode_tag(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;
    return PyInt_FromLong(c->node->tag);
}

static PyObject *confdCsNode_parent(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;
    if (c->node->parent) {
        return newConfdCsNode(c->node->parent);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsNode_children(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;
    if (c->node->children) {
        return newConfdCsNode(c->node->children);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsNode_next(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;
    if (c->node->next) {
        return newConfdCsNode(c->node->next);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsNode_info(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;
    return newConfdCsNodeInfo(&c->node->info);
}

static PyObject *confdCsNode_is_action(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_ACTION) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_case(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_CASE) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static int confdCsNode_internal_is_container(confdCsNode *c)
{
    if (c->node->info.flags & CS_NODE_IS_CONTAINER) {
        return 1;
    }
    return 0;
}

static PyObject *confdCsNode_is_container(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_container(c)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_np_container(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_container(c) &&
            c->node->info.minOccurs == 1) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_p_container(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_container(c) &&
            c->node->info.minOccurs == 0) {
        Py_RETURN_TRUE;
    }
    Py_RETURN_FALSE;
}

static int confdCsNode_internal_is_leaf(confdCsNode *c)
{
    if (c->node->children == NULL) {
        if ((c->node->info.flags & (CS_NODE_IS_CONTAINER |
                                    CS_NODE_IS_LIST |
                                    CS_NODE_IS_ACTION |
                                    CS_NODE_IS_NOTIF |
                                    CS_NODE_IS_LEAF_LIST)) == 0) {
            return 1;
        }
    }

    return 0;
}

static PyObject *confdCsNode_is_leaf(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_leaf(c)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_empty_leaf(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_leaf(c) &&
            c->node->info.shallow_type == C_XMLTAG) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_non_empty_leaf(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_leaf(c) &&
            c->node->info.shallow_type != C_XMLTAG) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_key(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (confdCsNode_internal_is_leaf(c) &&
        c->node->parent &&
        c->node->parent->info.flags & CS_NODE_IS_LIST &&
        c->node->parent->info.keys) {

        int count = 0;
        u_int32_t *p = c->node->parent->info.keys;
        while (*p++ != 0) {
            count++;
        }
        if (count > 0) {
            int i;
            for (i = 0; i < count; i++) {
                if (c->node->parent->info.keys[i] == c->node->tag) {
                    Py_RETURN_TRUE;
                }
            }
        }
    }
    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_leaf_list(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_LEAF_LIST) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_list(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_LIST) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_action_param(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_PARAM) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_action_result(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_RESULT) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_writable(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & (CS_NODE_IS_WRITE|CS_NODE_IS_WRITE_ALL)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_notif(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_NOTIF) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_oper(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (!(c->node->info.flags & CS_NODE_IS_WRITE)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_has_when(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_HAS_WHEN) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_has_display_when(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_HAS_DISPLAY_WHEN) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_leafref(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_IS_LEAFREF) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyObject *confdCsNode_is_mount_point(PyObject *self)
{
    confdCsNode *c = (confdCsNode*)self;

    if (c->node->info.flags & CS_NODE_HAS_MOUNT_POINT) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}


static PyMethodDef confdCsNode_methods[] = {
    MTH_DEF(confdCsNode, ns, METH_NOARGS),
    MTH_DEF(confdCsNode, tag, METH_NOARGS),
    MTH_DEF(confdCsNode, parent, METH_NOARGS),
    MTH_DEF(confdCsNode, children, METH_NOARGS),
    MTH_DEF(confdCsNode, next, METH_NOARGS),
    MTH_DEF(confdCsNode, info, METH_NOARGS),
    MTH_DEF(confdCsNode, is_action, METH_NOARGS),
    MTH_DEF(confdCsNode, is_case, METH_NOARGS),
    MTH_DEF(confdCsNode, is_container, METH_NOARGS),
    MTH_DEF(confdCsNode, is_p_container, METH_NOARGS),
    MTH_DEF(confdCsNode, is_np_container, METH_NOARGS),
    MTH_DEF(confdCsNode, is_empty_leaf, METH_NOARGS),
    MTH_DEF(confdCsNode, is_non_empty_leaf, METH_NOARGS),
    MTH_DEF(confdCsNode, is_leaf, METH_NOARGS),
    MTH_DEF(confdCsNode, is_leaf_list, METH_NOARGS),
    MTH_DEF(confdCsNode, is_key, METH_NOARGS),
    MTH_DEF(confdCsNode, is_list, METH_NOARGS),
    MTH_DEF(confdCsNode, is_action_param, METH_NOARGS),
    MTH_DEF(confdCsNode, is_action_result, METH_NOARGS),
    MTH_DEF(confdCsNode, is_writable, METH_NOARGS),
    MTH_DEF(confdCsNode, is_notif, METH_NOARGS),
    MTH_DEF(confdCsNode, is_oper, METH_NOARGS),
    MTH_DEF(confdCsNode, has_when, METH_NOARGS),
    MTH_DEF(confdCsNode, has_display_when, METH_NOARGS),
    MTH_DEF(confdCsNode, is_leafref, METH_NOARGS),
    MTH_DEF(confdCsNode, is_mount_point, METH_NOARGS),
    {NULL}  /* Sentinel */
};

static int setup_type_confd_csnode(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdCsNode_new },
        { .slot = Py_tp_init,        .pfunc = confdCsNode_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdCsNode_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdCsNode_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdCsNode__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdCsNode_repr },
        { .slot = Py_tp_str,         .pfunc = confdCsNode_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".CsNode",
        .basicsize = sizeof(confdCsNode),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdCsNodeType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdCsNodeType == NULL)
        return -1;
    return 0;
}

PyObject* newConfdCsNode(struct confd_cs_node *node)
{
    confdCsNode *self = (confdCsNode*)
        PyObject_New(confdCsNode, confdCsNodeType);

    if (self != NULL) {
        self->node = node;
    }

    return (PyObject *) self;
}

int isConfdCsNode(PyObject *o)
{
    return o->ob_type == confdCsNodeType;
}

/* ************************************************************************ */
/* confd_cs_node_info -> confd.CsNodeInfo                              */
/* ************************************************************************ */

static void confdCsNodeInfo_dealloc(confdCsNodeInfo *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdCsNodeInfo_str(confdCsNodeInfo *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".CsNodeInfo");
}


static PyObject *confdCsNodeInfo_repr(confdCsNodeInfo *self)
{
    return confdCsNodeInfo_str(self);
}

static int confdCsNodeInfo_init(confdCsNodeInfo *self,
                              PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdCsNodeInfo_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_TypeError,
            "Can't instantiate "
            CONFD_PY_MODULE ".CsNodeInfo from Python");

    return NULL;
}

static PyObject *confdCsNodeInfo_keys(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;

    if (c->info.keys) {
        int count = 0;
        u_int32_t *p = c->info.keys;
        while (*p++ != 0) {
            count++;
        }
        if (count > 0) {
            PyObject *ret = PyList_New(count);
            int i;
            for (i = 0; i < count; i++) {
                PyList_SetItem(ret, i, PyInt_FromLong(c->info.keys[i]));
            }
            return ret;
        }
    }

    Py_RETURN_NONE;
}

static PyObject *confdCsNodeInfo_min_occurs(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    return PyInt_FromLong(c->info.minOccurs);
}

static PyObject *confdCsNodeInfo_max_occurs(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    return PyInt_FromLong(c->info.maxOccurs);
}

static PyObject *confdCsNodeInfo_shallow_type(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    return PyInt_FromLong(c->info.shallow_type);
}

static PyObject *confdCsNodeInfo_type(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    if (c->info.type) {
        return newConfdCsType(c->info.type);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsNodeInfo_defval(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    if (c->info.defval)
        return (PyObject*)PyConfd_Value_New_DupTo(c->info.defval);
    else
        Py_RETURN_NONE;
}

static PyObject *confdCsNodeInfo_choices(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    if (c->info.choices) {
        return newConfdCsChoice(c->info.choices);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsNodeInfo_flags(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    return PyInt_FromLong(c->info.flags);
}

static PyObject *confdCsNodeInfo_cmp(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    return PyInt_FromLong(c->info.cmp);
}

static PyObject *confdCsNodeInfo_meta_data(PyObject *self)
{
    confdCsNodeInfo *c = (confdCsNodeInfo*)self;
    if (c->info.meta_data) {
        struct confd_cs_meta_data *md = c->info.meta_data;
        PyObject *ret = PyDict_New();
        int i = 0;
        while (md[i].key != NULL) {
            if (c->info.meta_data[i].value == NULL) {
                PyDict_SetItemString(ret, md[i].key, Py_None);
            } else {
                PyObject *v = PyString_FromString(md[i].value);
                PyDict_SetItemString(ret, md[i].key, v);
                Py_DECREF(v);
            }
            i++;
        }
        return ret;
    }
    Py_RETURN_NONE;
}

static PyMethodDef confdCsNodeInfo_methods[] = {
    {"keys", (PyCFunction)confdCsNodeInfo_keys, METH_NOARGS,
        confdCsNodeInfo_keys__doc__
    },
    {"min_occurs", (PyCFunction)confdCsNodeInfo_min_occurs, METH_NOARGS,
        confdCsNodeInfo_min_occurs__doc__
    },
    {"max_occurs", (PyCFunction)confdCsNodeInfo_max_occurs, METH_NOARGS,
        confdCsNodeInfo_max_occurs__doc__
    },
    {"shallow_type", (PyCFunction)confdCsNodeInfo_shallow_type, METH_NOARGS,
        confdCsNodeInfo_shallow_type__doc__
    },
    {"type", (PyCFunction)confdCsNodeInfo_type, METH_NOARGS,
        confdCsNodeInfo_type__doc__
    },
    {"defval", (PyCFunction)confdCsNodeInfo_defval, METH_NOARGS,
        confdCsNodeInfo_defval__doc__
    },
    {"choices", (PyCFunction)confdCsNodeInfo_choices, METH_NOARGS,
        confdCsNodeInfo_choices__doc__
    },
    {"flags", (PyCFunction)confdCsNodeInfo_flags, METH_NOARGS,
        confdCsNodeInfo_flags__doc__
    },
    {"cmp", (PyCFunction)confdCsNodeInfo_cmp, METH_NOARGS,
        confdCsNodeInfo_cmp__doc__
    },
    {"meta_data", (PyCFunction)confdCsNodeInfo_meta_data, METH_NOARGS,
        confdCsNodeInfo_meta_data__doc__
    },
    {NULL}  /* Sentinel */
};

static int setup_type_confd_csnodeinfo(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdCsNodeInfo_new },
        { .slot = Py_tp_init,        .pfunc = confdCsNodeInfo_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdCsNodeInfo_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdCsNodeInfo_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdCsNodeInfo__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdCsNodeInfo_repr },
        { .slot = Py_tp_str,         .pfunc = confdCsNodeInfo_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".CsNodeInfo",
        .basicsize = sizeof(confdCsNodeInfo),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdCsNodeInfoType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdCsNodeInfoType == NULL)
        return -1;
    return 0;
}

PyObject* newConfdCsNodeInfo(struct confd_cs_node_info *info)
{
    confdCsNodeInfo *self = (confdCsNodeInfo*)
        PyObject_New(confdCsNodeInfo, confdCsNodeInfoType);

    if (self != NULL) {
        self->info = *info;
    }

    return (PyObject *) self;
}

int isConfdCsNodeInfo(PyObject *o)
{
    return o->ob_type == confdCsNodeInfoType;
}

/* ************************************************************************ */
/* confd_type -> confd.CsType                                          */
/* ************************************************************************ */

static void confdCsType_dealloc(confdCsType *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdCsType_str(confdCsType *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".CsType");
}


static PyObject *confdCsType_repr(confdCsType *self)
{
    return confdCsType_str(self);
}

static int confdCsType_init(confdCsType *self,
                              PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdCsType_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_TypeError,
            "Can't instantiate "
            CONFD_PY_MODULE ".CsType from Python");

    return NULL;
}

static PyObject *confdCsType_parent(PyObject *self)
{
    confdCsType *c = (confdCsType*)self;
    if (c->type->parent) {
        return newConfdCsType(c->type->parent);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsType_defval(PyObject *self)
{
    confdCsType *c = (confdCsType*)self;
    if (c->type->defval) {
        return newConfdCsType(c->type->defval);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsType_bitbig_size(PyObject *self)
{
    int size;
    confdCsType *c = (confdCsType*)self;

    EXT_API_TIMING_CALL_WRAP(
        CHECK_CONFD_ERR(size = confd_get_bitbig_size(c->type)));

    return PyInt_FromLong(size);
}


static PyMethodDef confdCsType_methods[] = {
    {"parent", (PyCFunction)confdCsType_parent, METH_NOARGS,
        confdCsType_parent__doc__
    },
    {"defval", (PyCFunction)confdCsType_defval, METH_NOARGS,
        confdCsType_defval__doc__
    },
    {"bitbig_size", (PyCFunction)confdCsType_bitbig_size, METH_NOARGS,
        confdCsType_bitbig_size__doc__
    },
    {NULL}  /* Sentinel */
};

static int setup_type_confd_cstype(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdCsType_new },
        { .slot = Py_tp_init,        .pfunc = confdCsType_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdCsType_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdCsType_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdCsType__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdCsType_repr },
        { .slot = Py_tp_str,         .pfunc = confdCsType_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".CsType",
        .basicsize = sizeof(confdCsType),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdCsTypeType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdCsTypeType == NULL)
        return -1;
    return 0;
}

PyObject* newConfdCsType(struct confd_type *type)
{
    confdCsType *self = (confdCsType*)
        PyObject_New(confdCsType, confdCsTypeType);

    if (self != NULL) {
        self->type = type;
    }

    return (PyObject *) self;
}

int isConfdCsType(PyObject *o)
{
    return o->ob_type == confdCsTypeType;
}

/* ************************************************************************ */
/* confd_cs_choice -> confd.CsChoice                                   */
/* ************************************************************************ */

static void confdCsChoice_dealloc(confdCsChoice *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdCsChoice_str(confdCsChoice *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".CsChoice");
}

static PyObject *confdCsChoice_repr(confdCsChoice *self)
{
    return confdCsChoice_str(self);
}

static int confdCsChoice_init(confdCsChoice *self,
                              PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdCsChoice_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_TypeError,
            "Can't instantiate "
            CONFD_PY_MODULE ".CsChoice from Python");

    return NULL;
}

static PyObject *confdCsChoice_ns(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    return PyInt_FromLong(c->choice->ns);
}

static PyObject *confdCsChoice_tag(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    return PyInt_FromLong(c->choice->tag);
}

static PyObject *confdCsChoice_min_occurs(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    return PyInt_FromLong(c->choice->minOccurs);
}

static PyObject *confdCsChoice_default_case(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    if (c->choice->default_case) {
        return newConfdCsCase(c->choice->default_case);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsChoice_parent(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    if (c->choice->parent) {
        return newConfdCsNode(c->choice->parent);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsChoice_cases(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    if (c->choice->cases) {
        return newConfdCsCase(c->choice->cases);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsChoice_next(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    if (c->choice->next) {
        return newConfdCsChoice(c->choice->next);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsChoice_case_parent(PyObject *self)
{
    confdCsChoice *c = (confdCsChoice*)self;
    if (c->choice->case_parent) {
        return newConfdCsCase(c->choice->case_parent);
    }
    Py_RETURN_NONE;
}


static PyMethodDef confdCsChoice_methods[] = {
    {"ns", (PyCFunction)confdCsChoice_ns, METH_NOARGS,
        confdCsChoice_ns__doc__,
    },
    {"tag", (PyCFunction)confdCsChoice_tag, METH_NOARGS,
        confdCsChoice_tag__doc__,
    },
    {"min_occurs", (PyCFunction)confdCsChoice_min_occurs, METH_NOARGS,
        confdCsChoice_min_occurs__doc__,
    },
    {"default_case", (PyCFunction)confdCsChoice_default_case, METH_NOARGS,
        confdCsChoice_default_case__doc__,
    },
    {"parent", (PyCFunction)confdCsChoice_parent, METH_NOARGS,
        confdCsChoice_parent__doc__,
    },
    {"cases", (PyCFunction)confdCsChoice_cases, METH_NOARGS,
        confdCsChoice_cases__doc__,
    },
    {"next", (PyCFunction)confdCsChoice_next, METH_NOARGS,
        confdCsChoice_next__doc__,
    },
    {"case_parent", (PyCFunction)confdCsChoice_case_parent, METH_NOARGS,
        confdCsChoice_case_parent__doc__,
    },
    {NULL}  /* Sentinel */
};

static int setup_type_confd_cschoice(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdCsChoice_new },
        { .slot = Py_tp_init,        .pfunc = confdCsChoice_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdCsChoice_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdCsChoice_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdCsChoice__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdCsChoice_repr },
        { .slot = Py_tp_str,         .pfunc = confdCsChoice_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".CsChoice",
        .basicsize = sizeof(confdCsChoice),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdCsChoiceType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdCsChoiceType == NULL)
        return -1;
    return 0;
}

PyObject* newConfdCsChoice(struct confd_cs_choice *choice)
{
    confdCsChoice *self = (confdCsChoice*)
        PyObject_New(confdCsChoice, confdCsChoiceType);

    if (self != NULL) {
        self->choice = choice;
    }

    return (PyObject *) self;
}

int isConfdCsChoice(PyObject *o)
{
    return o->ob_type == confdCsChoiceType;
}

/* ************************************************************************ */
/* confd_cs_case -> confd.CsCase                                       */
/* ************************************************************************ */

static void confdCsCase_dealloc(confdCsCase *self)
{
    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdCsCase_str(confdCsCase *self)
{
    return PyString_FromFormat(CONFD_PY_MODULE ".CsCase");
}

static PyObject *confdCsCase_repr(confdCsCase *self)
{
    return confdCsCase_str(self);
}

static int confdCsCase_init(confdCsCase *self,
                              PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdCsCase_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_TypeError,
            "Can't instantiate "
            CONFD_PY_MODULE ".CsCase from Python");

    return NULL;
}

static PyObject *confdCsCase_ns(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    return PyInt_FromLong(c->cscase->ns);
}

static PyObject *confdCsCase_tag(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    return PyInt_FromLong(c->cscase->tag);
}

static PyObject *confdCsCase_first(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    if (c->cscase->first) {
        return newConfdCsNode(c->cscase->first);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsCase_last(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    if (c->cscase->last) {
        return newConfdCsNode(c->cscase->last);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsCase_parent(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    if (c->cscase->parent) {
        return newConfdCsChoice(c->cscase->parent);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsCase_next(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    if (c->cscase->next) {
        return newConfdCsCase(c->cscase->next);
    }
    Py_RETURN_NONE;
}

static PyObject *confdCsCase_choices(PyObject *self)
{
    confdCsCase *c = (confdCsCase*)self;
    if (c->cscase->choices) {
        return newConfdCsChoice(c->cscase->choices);
    }
    Py_RETURN_NONE;
}

static PyMethodDef confdCsCase_methods[] = {
    MTH_DEF(confdCsCase, ns, METH_NOARGS),
    MTH_DEF(confdCsCase, tag, METH_NOARGS),
    MTH_DEF(confdCsCase, first, METH_NOARGS),
    MTH_DEF(confdCsCase, last, METH_NOARGS),
    MTH_DEF(confdCsCase, parent, METH_NOARGS),
    MTH_DEF(confdCsCase, next, METH_NOARGS),
    MTH_DEF(confdCsCase, choices, METH_NOARGS),
    {NULL}  /* Sentinel */
};

static int setup_type_confd_cscase(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdCsCase_new },
        { .slot = Py_tp_init,        .pfunc = confdCsCase_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdCsCase_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdCsCase_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdCsCase__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdCsCase_repr },
        { .slot = Py_tp_str,         .pfunc = confdCsCase_str },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".CsCase",
        .basicsize = sizeof(confdCsCase),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    confdCsCaseType = (PyTypeObject*)PyType_FromSpec(&spec);

    if (confdCsCaseType == NULL)
        return -1;
    return 0;
}

PyObject* newConfdCsCase(struct confd_cs_case *cscase)
{
    confdCsCase *self = (confdCsCase*)
        PyObject_New(confdCsCase, confdCsCaseType);

    if (self != NULL) {
        self->cscase = cscase;
    }

    return (PyObject *) self;
}

int isConfdCsCase(PyObject *o)
{
    return o->ob_type == confdCsCaseType;
}

/* ************************************************************************ */
/* struct confd_list_filter* -> _confd.dp.ListFilter                        */
/* ************************************************************************ */


static void confdListFilter_dealloc(confdListFilter *self)
{
    if (self->lf_owner) {
        Py_DECREF(self->lf_owner);
    } else {
        confd_free_list_filter(self->lf);
    }

    /* Normal dealloc */
    PY_TP_FREE(self);
}

static PyObject *confdListFilter_getattro(confdListFilter *self,
                                          PyObject *name_);

static PyObject *confdListFilter_str(confdListFilter *self)
{
    char *node = self->lf->node ? confd_hash2str(self->lf->node->tag) : NULL;
    char *val = self->lf->val ? _confd_value_str(self->lf->val) : NULL;
    PyObject *ret = PyString_FromFormat(
                CONFD_PY_MODULE ".dp.ListFilter"
                    "(type=%d, op=%d, node=%s, val=%s)",
                self->lf->type, self->lf->op,
                node ? node : "None", val ? val : "None");
    free(val);
    return ret;
}


static PyObject *confdListFilter_repr(confdListFilter *self)
{
    return confdListFilter_str(self);
}

static int confdListFilter_init(confdListFilter *self,
                                 PyObject *args, PyObject *kwds)
{
    return 0;
}

static PyObject *
confdListFilter_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyErr_Format(PyExc_NotImplementedError,
            "Can't instantiate "
            CONFD_PY_MODULE ".dp.ListFilter from Python");

    return NULL;
}

static PyObject *confdListFilter_getattro_c_str(confdListFilter *self,
                                                PyObject *name_,
                                                const char *name)
{
    if (strcmp(name, "type") == 0) {
        return PyInt_FromLong((long)self->lf->type);
    } else if (strcmp(name, "expr1") == 0) {
        if (self->lf->expr1) {
            return newConfdListFilter(self->lf->expr1, (PyObject*) self);
        }
        Py_RETURN_NONE;
    } else if (strcmp(name, "expr2") == 0) {
        if (self->lf->expr2) {
            return newConfdListFilter(self->lf->expr2, (PyObject*) self);
        }
        Py_RETURN_NONE;
    } else if (strcmp(name, "op") == 0) {
        return PyInt_FromLong((long)self->lf->op);
    } else if (strcmp(name, "node") == 0) {
        PyObject *ret = PyList_New(self->lf->nodelen);
        int i;
        PyObject *tag;
        for (i = 0; i < self->lf->nodelen; i++) {
            tag = PyConfd_XmlTag_New(&self->lf->node[i]);
            PyList_SetItem(ret, i, tag);
        }
        return ret;
    } else if (strcmp(name, "val") == 0) {
        if (self->lf->val) {
            return newConfdValue(self->lf->val);
        }
        Py_RETURN_NONE;
    }

    return PyObject_GenericGetAttr((PyObject *) self, name_);
}

static PyObject *confdListFilter_getattro(confdListFilter *self,
                                          PyObject *name_)
{
    if (!PyString_Check(name_)) {
        PyErr_Format(PyExc_TypeError, "name must be a string");
        return NULL;
    }

    PyObject *res;
    CONFD_PY_WITH_C_STR(name_, name) {
        res = confdListFilter_getattro_c_str(self, name_, name);
    }
    return res;
}

static PyMethodDef confdListFilter_methods[] = {
    {NULL}  /* Sentinel */
};

static int setup_type_confd_listfilterref(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_new,         .pfunc = confdListFilter_new },
        { .slot = Py_tp_init,        .pfunc = confdListFilter_init },
        { .slot = Py_tp_dealloc,     .pfunc = confdListFilter_dealloc },
        { .slot = Py_tp_methods,     .pfunc = confdListFilter_methods },
        { .slot = Py_tp_doc,         .pfunc = (void*)confdListFilter__doc__ },
        { .slot = Py_tp_repr,        .pfunc = confdListFilter_repr },
        { .slot = Py_tp_str,         .pfunc = confdListFilter_str },
        { .slot = Py_tp_getattro,    .pfunc = confdListFilter_getattro },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE ".dp.ListFilter",
        .basicsize = sizeof(confdListFilter),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
        .slots = slots
    };

    if ((confdListFilterType = (PyTypeObject*)PyType_FromSpec(&spec)) == NULL)
        return -1;
    return 0;
}

PyObject* newConfdListFilter(struct confd_list_filter *lf, PyObject *lf_owner)
{
    confdListFilter *self = (confdListFilter*)
        PyObject_New(confdListFilter, confdListFilterType);

    self->lf = lf;
    self->lf_owner = lf_owner;

    if (self->lf_owner) {
        Py_INCREF(self->lf_owner);
    }

    return (PyObject *) self;
}

int isConfdListFilter(PyObject *o)
{
    return PyObject_TypeCheck(o, confdListFilterType);
}

/* ************************************************************************ */
/* Type initializations                                                     */
/* ************************************************************************ */

void init_lib_types(PyObject *m)
{
    if (setup_type_confd_value() < 0)
        goto error;
    PyModule_AddObject(m, "Value", (PyObject *)confdValueType);

    if (!confdValue_iter_init(m))
        goto error;

    /* Setup of confd.TagValue */
    if (setup_type_confd_tagvalue() < 0)
        goto error;
    PyModule_AddObject(m, "TagValue", (PyObject *)confdTagValueType);

    /* Setup of confd.AttrValue */
    if (setup_type_confd_attrvalue() < 0)
        goto error;
    PyModule_AddObject(m, "AttrValue", (PyObject *)confdAttrValueType);

    /* Setup of confd.XmlTag */
    if (setup_type_confd_xmltag() < 0)
        goto error;
    PyModule_AddObject(m, "XmlTag", (PyObject *)confdXmlTagType);

    /* Setup of confd.HKeypathRef */
    if (setup_type_confd_hkeypathref() < 0)
        goto error;
    PyModule_AddObject(m, "HKeypathRef", (PyObject *)confdHKeypathRefType);

    /* Setup of confd.TransCtxRef */
    if (setup_type_confd_transctxref() < 0)
        goto error;
    PyModule_AddObject(m, "TransCtxRef", (PyObject *)confdTransCtxRefType);

    /* Setup of confd.UserInfo */
    if (setup_type_confd_userinfo() < 0)
        goto error;
    PyModule_AddObject(m, "UserInfo", (PyObject *)confdUserInfoType);

    /* Setup of confd.AuthorizationInfo */
    if (setup_type_confd_authorizationinfo() < 0)
        goto error;
    PyModule_AddObject(m, "AuthorizationInfo",
        (PyObject *)confdAuthorizationInfoType);

    /* Setup of confd.DateTime */
    if (setup_type_confd_datetime() < 0)
        goto error;
    PyModule_AddObject(m, "DateTime", (PyObject *)confdDateTimeType);

    /* Setup of confd.SnmpVarbind */
    if (setup_type_confd_snmpvarbind() < 0)
        goto error;
    PyModule_AddObject(m, "SnmpVarbind", (PyObject *)confdSnmpVarbindType);

    /* Setup of confd.QueryResult */
    if (setup_type_confd_queryresult() < 0)
        goto error;
    PyModule_AddObject(m, "QueryResult", (PyObject *)confdQueryResultType);

    /* Setup of confd.CsNode */
    if (setup_type_confd_csnode() < 0)
        goto error;
    PyModule_AddObject(m, "CsNode", (PyObject *)confdCsNodeType);

    /* Setup of confd.CsNodeInfo */
    if (setup_type_confd_csnodeinfo() < 0)
        goto error;
    PyModule_AddObject(m, "CsNodeInfo", (PyObject *)confdCsNodeInfoType);

    /* Setup of confd.CsType */
    if (setup_type_confd_cstype() < 0)
        goto error;
    PyModule_AddObject(m, "CsType", (PyObject *)confdCsTypeType);

    /* Setup of confd.CsChoice */
    if (setup_type_confd_cschoice() < 0)
        goto error;
    PyModule_AddObject(m, "CsChoice", (PyObject *)confdCsChoiceType);

    /* Setup of confd.CsCase */
    if (setup_type_confd_cscase() < 0)
        goto error;
    PyModule_AddObject(m, "CsCase", (PyObject *)confdCsCaseType);

    return;

error:
    PyErr_SetString(PyExc_ImportError,
            CONFD_PY_MODULE " types init failed");
}


void init_dp_types(PyObject *m)
{
    /* Setup of AuthCtxRef */
    if (setup_type_confd_authctxref() < 0)
        goto error;
    PyModule_AddObject(m, "AuthCtxRef", (PyObject *)confdAuthCtxRefType);

    /* Setup of AuthorizationCtxRef */
    if (setup_type_confd_authorizationctxref() < 0)
        goto error;
    PyModule_AddObject(m, "AuthorizationCtxRef",
        (PyObject *)confdAuthorizationCtxRefType);

    /* Setup of DaemonCtxRef */
    if (setup_type_confd_daemonctxref() < 0)
        goto error;
    PyModule_AddObject(m, "DaemonCtxRef", (PyObject *)confdDaemonCtxRefType);

    /* Setup of DbCtxRef */
    if (setup_type_confd_dbctxref() < 0)
        goto error;
    PyModule_AddObject(m, "DbCtxRef", (PyObject *)confdDbCtxRefType);

    /* Setup of NotificationCtxRef */
    if (setup_type_confd_notificationctxref() < 0)
        goto error;
    PyModule_AddObject(m, "NotificationCtxRef",
        (PyObject *)confdNotificationCtxRefType);

    /* Setup of TrItemRef */
    if (setup_type_confd_tritemref() < 0)
        goto error;
    PyModule_AddObject(m, "TrItemRef",
        (PyObject *)confdTrItemRefType);

    /* Setup of confd.ListFilter */
    if (setup_type_confd_listfilterref() < 0)
        goto error;
    PyModule_AddObject(m, "ListFilter", (PyObject *)confdListFilterType);

    return;

error:
    PyErr_SetString(PyExc_ImportError,
            CONFD_PY_MODULE ".dp types init failed");
}


void init_events_types(PyObject *m)
{
    /* Setup of NotificationsData */
    if (setup_type_confd_notificationsdata() < 0)
        goto error;
    PyModule_AddObject(m, "NotificationsData",
            (PyObject *)confdNotificationsDataType);

    /* Setup of Notification */
    if (setup_type_confd_notification() < 0)
        goto error;
    PyModule_AddObject(m, "Notification",
            (PyObject *)confdNotificationType);

    return;

error:
    PyErr_SetString(PyExc_ImportError,
            CONFD_PY_MODULE ".events types init failed");
}


void init_maapi_types(PyObject *m)
{
    /* Setup of MaapiRollback */
    if (setup_type_confd_maapirollback() < 0) {
        PyErr_SetString(PyExc_ImportError,
                CONFD_PY_MODULE ".maapi types init failed");
        return;
    }
    PyModule_AddObject(m, "MaapiRollback", (PyObject *)confdMaapiRollbackType);
}

/* ************************************************************************* */
/* Python PyConfd_Value_Object list helper functions                         */
/* ************************************************************************* */

void init_py_confd_value_t_list(py_confd_value_t_list_t *sl)
{
    sl->size = 0;
    sl->list = NULL;
}

int alloc_py_confd_value_t_list(PyObject *o, py_confd_value_t_list_t *sl,
                const char argname[])
{
    if (!PyList_CheckExact(o)) {
        PyErr_Format(PyExc_TypeError, "%s argument must be a list", argname);
        return 0;
    }

    sl->size = (int) PyList_Size(o);
    sl->list = malloc(sl->size * sizeof(confd_value_t));

    if (sl->list == NULL) {
        PyErr_Format(PyExc_MemoryError, "sl->list == NULL");
        return 0;
    }

    int c;

    for (c = 0; c < sl->size; c++) {
        PyObject *item = PyList_GetItem(o, c);

        if (!PyConfd_Value_CheckExact(item)) {
            PyErr_Format(PyExc_TypeError,
                    "%s[%d] must be a "
                    CONFD_PY_MODULE ".Value instance", argname, (int) c);

            free(sl->list);
            sl->list = NULL;

            return 0;
        }

        memcpy(&(sl->list[c]),
               PyConfd_Value_PTR((PyConfd_Value_Object *) item),
               sizeof(confd_value_t));
    }

    return 1;
}

void free_py_confd_value_t_list(py_confd_value_t_list_t *sl)
{
    if (sl->list != NULL) {
        free(sl->list);
    }
}

/* ************************************************************************* */
/* Python callback method argument check                                     */
/* ************************************************************************* */

int check_callback_method(PyObject *o, const char *cbname, int argcount)
{
    PyObject *method = PyObject_GetAttrString(o, cbname);

    if (method == NULL) {
        PyErr_Format(PyExc_Exception,
                "Callback object must implement a %s method", cbname);
        return 0;
    }

    if (!PyCallable_Check(method)) {
        PyErr_Format(PyExc_Exception,
                "Callback object attribute %s must be callable", cbname);
        Py_DECREF(method);
        return 0;
    }

    PyObject* fc = PyObject_GetAttrString(method, "__code__");

    if (fc == NULL) {
        PyErr_Format(PyExc_Exception,
                "Cannot determine number of argument of %s", cbname);
        Py_DECREF(method);
        return 0;
    }

    PyObject* ac = PyObject_GetAttrString(fc, "co_argcount");
    if (ac == NULL) {
        PyErr_Format(PyExc_Exception,
                "Cannot determine number of argument of %s", cbname);
        Py_DECREF(method);
        Py_DECREF(fc);
        return 0;
    }

    const int count = PyInt_AsLong(ac);
    int ret = 1;

    if (count != argcount) {
        PyErr_Format(PyExc_Exception,
                "Callback method %s must take exactly %d arguments "
                "(currently %d)", cbname, argcount, count);
        ret = 0;
    }

    Py_DECREF(method);
    Py_DECREF(fc);
    Py_DECREF(ac);

    return ret;
}

#undef MTH_DEF
