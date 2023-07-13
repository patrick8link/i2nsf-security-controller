#ifndef NCSCONFD_COMMON_H
#define NCSCONFD_COMMON_H

#include <confd.h>
#include "confdpy_config.h"

#define CONFD_PY_WITH_C_STR(OBJ, NAME) \
    PyObject *_## NAME ##obj_str = PyObject_Str((OBJ)); \
    PyObject *_## NAME ##obj_bytes = \
        PyUnicode_AsUTF8String(_## NAME ##obj_str);  \
    Py_DECREF(_## NAME ##obj_str); \
    char * NAME = PyBytes_AsString(_## NAME ##obj_bytes); \
    for (int _## NAME ##with_obj_loop = 1; _## NAME ##with_obj_loop; \
         _## NAME ##with_obj_loop = 0, \
         confd_py_decref(_## NAME ##obj_bytes))

typedef struct {
    int size;
    char **list;
} py_string_list_t;

typedef struct {
    int size;
    int *list;
} py_int_list_t;

typedef struct {
    int size;
    u_int32_t *list;
} py_u_int32_list_t;

typedef struct {
    int size;
    struct ncs_name_value *list;
} py_prop_list_t;

int confd_py_alloc_py_string_list(PyObject *o, py_string_list_t *sl,
                                  const char *argname);
void confd_py_free_py_string_list(py_string_list_t *sl);

int confd_py_alloc_py_int_list(PyObject *o, py_int_list_t *il,
                               const char *argname);
void confd_py_free_py_int_list(py_int_list_t *il);

int confd_py_alloc_py_u_int32_list(PyObject *o, py_u_int32_list_t *il,
                                   const char *argname);
void confd_py_free_py_u_int32_list(py_u_int32_list_t *il);

int sock_arg(PyObject *arg, void *sp);

int path_arg(PyObject *arg, void *sp);

#ifdef CONFD_PY_PRODUCT_NCS

int confd_py_alloc_py_prop_list(PyObject *o, py_prop_list_t *pl,
                                const char *argname);
void confd_py_free_py_prop_list(py_prop_list_t *pl);

#endif /* CONFD_PY_PRODUCT_NCS */

void confd_py_decref(PyObject *obj);
char *confd_py_string_strdup(PyObject *str);

#endif /* NCSCONFD_COMMON_H */
