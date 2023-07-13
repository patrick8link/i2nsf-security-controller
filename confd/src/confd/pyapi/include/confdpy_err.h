/*
 * Copyright 2013 Tail-F Systems AB
 */

#ifndef _CONFDPY_ERR_H
#define _CONFDPY_ERR_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "_error.h"

#ifdef CONFD_PY_EXT_API_TIMING
#include "ext_api_timing.h"
#else /* !CONFD_PY_EXT_API_TIMING */

#define EXT_API_TIMING_CALL_WRAP(E) E

#define EXT_API_FUN(NAME, ID)                                           \
    static PyObject *NAME(PyObject *self, PyObject *args,               \
                          PyObject *kwds)

#define EXT_API_CALL(E)                         \
    Py_BEGIN_ALLOW_THREADS                      \
    _res = E;                                   \
    Py_END_ALLOW_THREADS

#define EXT_API_CALL_NO_RES(E)                  \
    Py_BEGIN_ALLOW_THREADS                      \
    E;                                          \
    Py_END_ALLOW_THREADS

#endif /* CONFD_PY_EXT_API_TIMING */

/* A macro that checks for CONFD_ERR, if no error your function
 * proceeds, on error an exception is raised and your function
 * returns. Use the macro with care - if you have allocated objects
 * you will need to DECREF them on CONFD_ERR *before* invoking the macro */
#define CHECK_CONFD_ERR(E) {                                    \
    int _res;                                                   \
    EXT_API_CALL(E)                                             \
    if (_res == CONFD_ERR) {                                    \
        return confdPyConfdError();                             \
    } else if (_res == CONFD_EOF) {                             \
        return confdPyEofError();                               \
    }                                                           \
}

/* Same as above, except if no err return V, else decref(V) before
 * returning error */
#define CONFD_RET_CHECK_ERR(E, V, ...) {                        \
    int _res;                                                   \
    EXT_API_CALL(E)                                             \
    __VA_ARGS__;                                                \
    if (_res == CONFD_ERR) {                                    \
        Py_XDECREF((PyObject *)(V));                            \
        return confdPyConfdError();                             \
    } else if (_res == CONFD_EOF) {                             \
        Py_XDECREF((PyObject *)(V));                            \
        return confdPyEofError();                               \
    }                                                           \
    return (PyObject *)(V);                                     \
}

/* Same as above, except if no err no return, else decref(V) before
 * returning error */
#define CONFD_RET_ON_ERR(E, V) {                                \
    int _res;                                                   \
    EXT_API_CALL(E)                                             \
    if (_res == CONFD_ERR) {                                    \
        Py_XDECREF((PyObject *)(V));                            \
        return confdPyConfdError();                             \
    } else if (_res == CONFD_EOF) {                             \
        Py_XDECREF((PyObject *)(V));                            \
        return confdPyEofError();                               \
    }                                                           \
}

/* Same as CHECK_CONFD_ERR(E), with the addition of always
 * executing F directly after E - useful for cleanup actions */
#define CHECK_CONFD_ERR_EXEC(E, F) {                            \
    int _res;                                                   \
    EXT_API_CALL(E)                                             \
    F;                                                          \
    if (_res == CONFD_ERR) {                                    \
        return confdPyConfdError();                             \
    } else if (_res == CONFD_EOF) {                             \
        return confdPyEofError();                               \
    }                                                           \
}

/* Same as CHECK_CONFD_ERR_EXEC(E, F), but only execute F in    \
 * case of error */
#define CHECK_CONFD_ERR_EXECERR(E, F) {                         \
    int _res;                                                   \
    EXT_API_CALL(E)                                             \
    if (_res == CONFD_ERR) {                                    \
        F;                                                      \
        return confdPyConfdError();                             \
    } else if (_res == CONFD_EOF) {                             \
        F;                                                      \
        return confdPyEofError();                               \
    }                                                           \
}

/* Execute E */
#define CONFD_EXEC(E) {                                         \
    EXT_API_CALL_NO_RES(E)                                      \
}


#ifdef __cplusplus
}
#endif

#endif
