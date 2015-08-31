import os
import re
import sys
import random
import inspect
import operator

fst = operator.itemgetter(0)
snd = operator.itemgetter(1)

PY2 = sys.version_info[0] == 2
text_type = unicode
_windows_device_files = ('CON', 'AUX', 'COM1', 'COM2', 'COM3', 'COM4', 'LPT1',
                         'LPT2', 'LPT3', 'PRN', 'NUL')

safe_chrs = map(chr, range(48,58)+range(65,91)+range(97,123))

def random_string(n=32, chrs=safe_chrs):
    return "".join([random.choice(chrs) for _ in range(n)])


def get_counter_state(c):
    return c.__reduce__()[1][0]

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


def stdin_open(fname, *args, **kwargs):
    msg = kwargs.pop('stdin_msg', None)
    if not fname or fname == "-":
        if msg:
            print >> sys.stderr, msg
        return sys.stdin
    else:
        return open(fname, *args, **kwargs)
    

# Thanks, werkzeug team!
_filename_ascii_strip_re = re.compile(r'[^A-Za-z0-9_.-]')
def secure_filename(filename):
    r"""Pass it a filename and it will return a secure version of it.  This
    filename can then safely be stored on a regular file system and passed
    to :func:`os.path.join`.  The filename returned is an ASCII only string
    for maximum portability.

    On windows systems the function also makes sure that the file is not
    named after one of the special device files.

    >>> secure_filename("My cool movie.mov")
    'My_cool_movie.mov'
    >>> secure_filename("../../../etc/passwd")
    'etc_passwd'
    >>> secure_filename(u'i contain cool \xfcml\xe4uts.txt')

    'i_contain_cool_umlauts.txt'
    The function might return an empty filename.  It's your responsibility
    to ensure that the filename is unique and that you generate random
    filename if the function returned an empty one.

    :param filename: the filename to secure
    """
    if isinstance(filename, text_type):
        from unicodedata import normalize
        filename = normalize('NFKD', filename).encode('ascii', 'ignore')
        if not PY2:
            filename = filename.decode('ascii')
    for sep in os.path.sep, os.path.altsep:
        if sep:
            filename = filename.replace(sep, ' ')
    filename = str(_filename_ascii_strip_re.sub('', '_'.join(
                   filename.split()))).strip('._')

    # on nt a couple of special files are present in each folder.  We
    # have to ensure that the target file is not such a filename.  In
    # this case we prepend an underline
    if os.name == 'nt' and filename and \
       filename.split('.')[0].upper() in _windows_device_files:
        filename = '_' + filename

    return filename
