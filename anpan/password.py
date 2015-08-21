import os
import time
import hmac
from collections import namedtuple

import pbkdf2

DEFAULT_SALT_LEN = 32
DEFAULT_COST_FACTOR = 5000
DEFAULT_HASHLEN = 32

#thanks @mitsuhiko!
def _safe_str_cmp(a, b):
    """avoids timing attacks by taking the same amount of time whether it
    hits a mismatch early or late"""
    if len(a) != len(b):
        return False
    rv = 0
    for x, y in izip(a, b):
        rv |= ord(x) ^ ord(y)
    return rv == 0


def compare(a, b):
    return _safe_str_cmp(split(a).hash, split(b).hash)


def salt(size_bytes=DEFAULT_SALT_LEN):
    return os.urandom(size_bytes)


HashedPassword = namedtuple("HashedPassword",
                            ["algorithm", "salt", "cost", "hash"])

def split(hash_str):
    algo, b, actual_hash = hash_str.split("$")
    salt_str, cost = b.split(":")
    return HashedPassword(algo, salt_str, cost, actual_hash)


def hash(raw_password, salt_str=None, iters=DEFAULT_COST_FACTOR,
         keylen=DEFAULT_HASHLEN, do_serialize=False):
    algo = "pbkdf2-256"
    if not salt_str:
        salt_str = salt()
    hash_str = pbkdf2.pbkdf2_hex(raw_password, salt_str, iterations=iters,
                                 keylen=keylen)
    if do_serialize:
        return serialize(algo, salt_str, iters, hash_str)
    else:
        return HashedPassword(algo, salt_str, iters, hash_str)


def serialize(algo, salt, cost, hash):
    return "{}${}:{}${}".format(algo, salt, cost, hash)


def token(hash_obj, the_time=None):
    if not the_time:
        the_time = time.time()
    return hmac.new(hash_obj.hash, str(the_time)).hexdigest()


def is_hashed(s):
    try:
        split(s)
    except:
        return False
    else:
        return True

