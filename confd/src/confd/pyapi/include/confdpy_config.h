/*
 * Copyright 2013 Tail-F Systems AB
 */

#ifndef CONFDPY_CONFIG_H
#define CONFDPY_CONFIG_H

#define Py_LIMITED_API 0x03070000
#include <Python.h>

#if PY_VERSION_HEX < 0x03070000
#error "At least Python 3.7 is needed to build the Python API."
#endif

typedef void (*TpFreeFn)(PyObject*);
typedef PyObject *(*TpAllocFn)(PyTypeObject*, Py_ssize_t);

#define PY_TP_ALLOC(type) \
    ((TpAllocFn)PyType_GetSlot(type, Py_tp_alloc))(type, 0);
#define PY_TP_FREE(obj) \
    ((TpFreeFn)PyType_GetSlot(Py_TYPE(obj), Py_tp_free))((PyObject*)obj);

#define PyString_Size(obj)  PyUnicode_GetLength(obj)

/* FIXME:  no need to define these anymore */
#define PyString_FromFormat PyUnicode_FromFormat
#define PyString_FromString PyUnicode_FromString
#define PyString_FromStringAndSize PyUnicode_FromStringAndSize
#define PyString_Check PyUnicode_Check

#define PyInt_FromLong PyLong_FromLong
#define PyInt_AsLong PyLong_AsLong
#define PyInt_Check PyLong_Check
#define PyNumber_Int PyNumber_Long
#define PyInt_Type PyLong_Type
#define PyString_Type PyUnicode_Type

/* Module and product name definitions */
#if CONFD_PY_PRODUCT_CONFD

#define CONFD_PY_MODULE "_confd"
#define CONFD_PY_PRODUCT "ConfD"

#elif CONFD_PY_PRODUCT_NCS

#define CONFD_PY_MODULE "_ncs"
#define CONFD_PY_PRODUCT "NCS"

#else
#error "CONFD_PY_PRODUCT_CONFD or CONFD_PY_PRODUCT_NCS must be defined"
#endif

#endif //CONFDPY_CONFIG_H
