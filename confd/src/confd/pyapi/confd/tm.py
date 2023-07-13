"""Internally used classes and functions."""

import functools

TM = '_confd'


def ncs_only(fn):
    """Decorator for NCS specific functions."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        raise Exception('This method is only available to NCS')
    return wrapper
