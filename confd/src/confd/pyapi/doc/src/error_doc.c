/*
 * dp documentation to be included in _ha.c
 */

#define ERROR_MODULE_DOCSTR(PROD) \
"This module defines new " PROD " Python API exception classes.\n"\
"\n"\
"Instead of checking for CONFD_ERR or CONFD_EOF return codes all Python\n"\
"module APIs raises an exception instead."

#define DOC(name) PyDoc_STRVAR(_error_ ## name ## __doc__,

/* ------------------------------------------------------------------------- */
DOC(Error)
/* ------------------------------------------------------------------------- */
"This exception will be thrown from an API function that, from a C perspective,"
"\n"
"would result in a CONFD_ERR return value.\n\n"

"Available attributes:\n\n"

"* confd_errno -- the underlying error number\n"
"* confd_strerror -- string representation of the confd_errno\n"
"* confd_lasterr -- string with additional textual information\n"
"* strerror -- os error string (available if confd_errno is CONFD_ERR_OS)"
);

/* ------------------------------------------------------------------------- */
DOC(EOF)
/* ------------------------------------------------------------------------- */
"This exception will be thrown from an API function that, from a C perspective,"
"\n"
"would result in a CONFD_EOF return value."
);

#undef DOC
