// include first, order is significant to get defines correct
#include "confdpy_config.h"

#include "common.h"

static void _init_py_string_list(py_string_list_t *sl)
{
    sl->size = 0;
    sl->list = NULL;
}

int confd_py_alloc_py_string_list(PyObject *o, py_string_list_t *sl,
                                  const char *argname)
{
    _init_py_string_list(sl);

    if (!PyList_CheckExact(o)) {
        PyErr_Format(PyExc_TypeError, "%s argument must be a list", argname);
        return 0;
    }

    sl->size = (int) PyList_Size(o);
    sl->list = calloc(sl->size, sizeof(char *));

    if (sl->list == NULL) {
        PyErr_Format(PyExc_MemoryError, "sl->list == NULL");
        return 0;
    }

    for (int c = 0; c < sl->size; c++) {
        PyObject *item = PyList_GetItem(o, c);

        if (!PyString_Check(item)) {
            PyErr_Format(PyExc_TypeError,
                    "%s[%d] must be a string", argname, (int) c);
            confd_py_free_py_string_list(sl);
            return 0;
        }

        sl->list[c] = confd_py_string_strdup(item);
    }

    return 1;
}

void confd_py_free_py_string_list(py_string_list_t *sl)
{
    if (sl->list != NULL) {
        for (int i = 0; i < sl->size; i++) {
            free(sl->list[i]);
        }
        free(sl->list);
        _init_py_string_list(sl);
    }
}

/* Function that can be passed to PyArg_ParseTuple() using the O&
 * format to fetch the filedescriptor from the socket object. */
int sock_arg(PyObject *arg, void *sp)
{
    int *s = (int *)sp;
    PyObject *sock;
    if ((sock = PyObject_CallMethod(arg, "fileno", NULL)) == NULL) {
        /* CallMethod sets up the exception */
        return 0;
    }
    *s = (int)PyInt_AsLong(sock);
    Py_DECREF(sock);
    return 1;
}

// Python Strings must be treated as literal string in the C-api. To do
// so we need to normalize the formatting such that all printf %-like
// formatting is padded and denoted as such
const char *PyConfd_NormalizeFormatString(const char *path)
{
    const char *fp = path;
    // Determine the length of the extended string
    int len = 1; // account for termination-character
    for (; *fp; fp++, len++) {
        if (*fp == '%') {
            len++;
        }
    }

    // Allocate enough space for the string and padding
    char *dp = malloc(len);
    char *fmt_path = dp;

    // Add padding for '%' characters to be escaped in CAPI
    fp = path;
    while (*fp != '\0') {
        *dp = *fp;
        dp++;
        if (*fp == '%') {
            *dp = '%';
            dp++;
        }
        fp++;
    }
    *dp = '\0';

    // We can 'forget' the path since the memory is managed by Python API
    return fmt_path;
}

int path_arg(PyObject *arg, void *sp)
{
    const char **ps = (const char **)sp;
    if (PyUnicode_Check(arg)) {
        CONFD_PY_WITH_C_STR(arg, path){
            *ps = PyConfd_NormalizeFormatString(path);
        }
        return 1;
    } else if (arg == Py_None) {
        // We will treat the parse tuple as though it is given the 'z'
        // parameter and return the empty null-terminated string in the case
        // of None.
        *ps = NULL;
        return 1;
    } else {
        // Raise exception
        PyErr_SetString(PyExc_TypeError,
                "path argument must be a string literal");
        return 0;
    }
}

static void _init_py_int_list(py_int_list_t *il)
{
    il->size = 0;
    il->list = NULL;
}

int confd_py_alloc_py_int_list(PyObject *o, py_int_list_t *il,
                               const char *argname)
{
    _init_py_int_list(il);

    if (!PyList_CheckExact(o)) {
        PyErr_Format(PyExc_TypeError, "%s argument must be a list", argname);
        return 0;
    }

    il->size = (int) PyList_Size(o);
    il->list = malloc(il->size * sizeof(int *));

    if (il->list == NULL) {
        PyErr_Format(PyExc_MemoryError, "il->list == NULL");
        return 0;
    }

    for (int c = 0; c < il->size; c++) {
        PyObject *item = PyList_GetItem(o, c);

        if (!PyInt_Check(item)) {
            PyErr_Format(PyExc_TypeError,
                    "%s[%d] must be an int", argname, (int) c);

            free(il->list);
            il->list = NULL;

            return 0;
        }

        il->list[c] = (int) PyInt_AsLong(item);
    }

    return 1;
}

void confd_py_free_py_int_list(py_int_list_t *il)
{
    if (il->list != NULL) {
        free(il->list);
        _init_py_int_list(il);
    }
}

static void _init_py_u_int32_list(py_u_int32_list_t *il)
{
    il->size = 0;
    il->list = NULL;
}

int confd_py_alloc_py_u_int32_list(PyObject *o, py_u_int32_list_t *il,
                                   const char *argname)
{
    _init_py_u_int32_list(il);

    if (!PyList_CheckExact(o)) {
        PyErr_Format(PyExc_TypeError, "%s argument must be a list", argname);
        return 0;
    }

    il->size = (int) PyList_Size(o);
    il->list = malloc(il->size * sizeof(int *));

    if (il->list == NULL) {
        PyErr_Format(PyExc_MemoryError, "il->list == NULL");
        return 0;
    }

    for (int c = 0; c < il->size; c++) {
        PyObject *item = PyList_GetItem(o, c);

        if (!PyInt_Check(item)) {
            PyErr_Format(PyExc_TypeError,
                         "%s[%d] must be an unsigned int32", argname, c);

            free(il->list);
            il->list = NULL;

            return 0;
        }

        il->list[c] = (u_int32_t) PyInt_AsLong(item);
    }

    return 1;
}

void confd_py_free_py_u_int32_list(py_u_int32_list_t *il)
{
    if (il->list != NULL) {
        free(il->list);
        _init_py_u_int32_list(il);
    }
}

#ifdef CONFD_PY_PRODUCT_NCS

static void _init_py_prop_list(py_prop_list_t *pl)
{
    pl->size = 0;
    pl->list = NULL;
}

int confd_py_alloc_py_prop_list(PyObject *variables, py_prop_list_t *pl,
                                const char *argname)
{
    _init_py_prop_list(pl);

    if (!PyList_Check(variables)) {
        PyErr_Format(PyExc_TypeError,
                     "%s must be a list of tuples or None", argname);
        return 0;
    }

    pl->size = (int)PyList_Size(variables);
    pl->list = (struct ncs_name_value *)
        calloc(pl->size, sizeof(struct ncs_name_value));

    PyObject *name = NULL;
    PyObject *value = NULL;
    for (int i = 0; i < pl->size; i++) {
        PyObject *variable = PyList_GetItem(variables, i);
        name = PyTuple_GetItem(variable, 0);
        if (!PyString_Check(name)) {
            confd_py_free_py_prop_list(pl);
            PyErr_Format(PyExc_TypeError,
                         "%s[%d][0] must be an string", argname, i);
            return 0;
        }
        value = PyTuple_GetItem(variable, 1);
        if (!PyString_Check(value)) {
            confd_py_free_py_prop_list(pl);
            PyErr_Format(PyExc_TypeError,
                         "%s[%d][1] must be an string", argname, i);
            return 0;
        }
        pl->list[i].name = confd_py_string_strdup(name);
        pl->list[i].value = confd_py_string_strdup(value);
    }

    return 1;
}

void confd_py_free_py_prop_list(py_prop_list_t *pl)
{
    for (int i = 0; i < pl->size; i++) {
        if (pl->list[i].name == NULL) {
            break;
        }
        free(pl->list[i].name);
        if (pl->list[i].value == NULL) {
            break;
        }
        free(pl->list[i].value);
    }
    free(pl->list);

    _init_py_prop_list(pl);
}

#endif /* CONFD_PY_PRODUCT_NCS */

void confd_py_decref(PyObject *obj)
{
    Py_DECREF(obj);
}

char *confd_py_string_strdup(PyObject *str)
{
    char *dup_str;
    CONFD_PY_WITH_C_STR(str, c_str) {
        dup_str = strdup(c_str);
    }
    return dup_str;
}
