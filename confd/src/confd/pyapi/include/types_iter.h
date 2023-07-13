/*
 * Copyright 2015 Tail-F Systems AB
 */

#ifndef NCSCONFD_TYPES_ITER_H
#define NCSCONFD_TYPES_ITER_H


typedef struct {
    PyObject_HEAD
    PyConfd_Value_Object *obj;
    unsigned int i;
} PyConfd_Value_Iter;


extern int confdValue_iter_init(PyObject *m);
extern PyObject *confdValue_iter(PyObject *obj);


#endif // NCSCONFD_TYPES_ITER_H
