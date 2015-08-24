import os
import re
import sys
import inspect


def stat(path, f):
    return os.stat(
        os.path.join(path,f)
        )

class retcodes:
    SYS_ERROR  = 2
    USER_ERROR = 1


def generator_flatten(gen):
    for item in gen:
        if inspect.isgenerator(item):
            for value in generator_flatten(item):
                yield value
        else:
            yield item


def islambda(func):
    return getattr(func,'func_name') == '<lambda>'


def rmext(name_str):
    """removes file extensions"""
    path, name_str = os.path.split(name_str)
    match = re.match(r'(.+)(\..*)', name_str)
    if match:
        noext = match.group(1)
    else:
        noext = name_str

    return os.path.join(path, noext)


def stdin_open(fname, *args, **kwargs):
    if not fname or fname == "-":
        if "stdin_msg" in kwargs:
            print >> sys.stderr, kwargs['stdin_msg']
        return sys.stdin
    else:
        return open(fname, *args, **kwargs)
    
