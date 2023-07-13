/*
 * Copyright 2005-2013 Tail-F Systems AB
 */

#ifndef _CONFDPY_ERROR_H
#define _CONFDPY_ERROR_H 1

#ifdef __cplusplus
extern "C" {
#endif

extern PyObject* init__error_module(void);

extern PyObject *ConfdError; /* pointer to confd.Error exception object */

extern PyObject* confdPyConfdError(void);
extern PyObject* confdPyEofError(void);
extern PyObject* confdPyNotImplementedError(void);
extern PyObject* confdPyDeprecatedFunctionError(void);

#ifdef __cplusplus
}
#endif
#endif

