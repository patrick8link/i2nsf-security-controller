// include first, order is significant to get defines correct
#include "confdpy_config.h"

#include "types.h"
#include "types_iter.h"


#define PYITER_CHECK(obj) (PyType_GetSlot(Py_TYPE(obj), Py_tp_iternext) != NULL)

PyTypeObject *PyConfd_Value_Iter_Type = NULL;

PyObject *confdValue_iter_self(PyObject *obj);
PyObject *confdValue_iternext(PyObject *obj);

/* ------------------------------------------------------------------------- */

static void confdValue_iter_dealloc(PyObject *obj)
{
    PyConfd_Value_Iter *iter = (PyConfd_Value_Iter*)obj;
    Py_DECREF(iter->obj);
    PyObject_Del(obj);
}

/* ------------------------------------------------------------------------- */

static int setup_type_confd_value_iter(void)
{
    PyType_Slot slots[] = {
        { .slot = Py_tp_dealloc,     .pfunc = confdValue_iter_dealloc },
        { .slot = Py_tp_doc,         .pfunc = "confd value_t object iterator" },
        { .slot = Py_tp_iter,        .pfunc = confdValue_iter_self },
        { .slot = Py_tp_iternext,    .pfunc = confdValue_iternext },
        { .slot = 0, .pfunc = 0 }
    };

    PyType_Spec spec = {
        .name = CONFD_PY_MODULE "._ValueIter",
        .basicsize = sizeof(PyConfd_Value_Iter),
        .itemsize = 0,
        .flags = Py_TPFLAGS_DEFAULT,
        .slots = slots
    };

    PyConfd_Value_Iter_Type = (PyTypeObject*)PyType_FromSpec(&spec);

    if (PyConfd_Value_Iter_Type == NULL)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------------- */

PyObject *confdValue_iter_self(PyObject *obj)
{
    return obj;
}

/* ------------------------------------------------------------------------- */
PyObject *confdValue_iter(PyObject *obj)
{
    if (PyConfd_Value_CheckExact(obj)) {
        PyConfd_Value_Iter *iter;

        /* only C_LIST:s are iterable */
        if (((PyConfd_Value_Object*)obj)->ob_val.type != C_LIST) {
            PyErr_SetString(PyExc_TypeError,
                            "only values of type C_LIST are iterable");
            return NULL;
        }

        iter = PyObject_New(PyConfd_Value_Iter, PyConfd_Value_Iter_Type);
        if (!iter) {
            return NULL;
        }
        Py_INCREF(obj);
        iter->obj = (PyConfd_Value_Object*)obj;
        iter->i = 0;
        return (PyObject*)iter;
    }

    if (!PYITER_CHECK(obj)) {
        PyErr_SetString(PyExc_TypeError, "iteration over non-sequence");
        return NULL;
    }

    Py_INCREF(obj);
    return obj;
}

/* ------------------------------------------------------------------------- */

PyObject *confdValue_iternext(PyObject *obj)
{
    PyConfd_Value_Iter *iter = (PyConfd_Value_Iter*)obj;

    if (iter->i >= iter->obj->ob_val.val.list.size) {
        PyErr_SetNone(PyExc_StopIteration);
        return NULL;
    }

    {
        PyConfd_Value_Object *item =
            PyConfd_Value_New_DupTo(
                    &(iter->obj->ob_val.val.list.ptr[iter->i]));
        (iter->i)++;
        return (PyObject*)item;
    }
}

/* ------------------------------------------------------------------------- */

int confdValue_iter_init(PyObject *m)
{
    if (setup_type_confd_value_iter() < 0)
        return 0;
    PyModule_AddObject(m, "_ValueIter", (PyObject*)PyConfd_Value_Iter_Type);
    return 1;
}
