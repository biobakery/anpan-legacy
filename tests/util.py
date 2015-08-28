import inspect

from anpan import util
from anpan.util import serialize, deserialize

def test_generator_flatten():
    def a():
        for i in range(3):
            yield iter(j for j in range(i))

    def b():
        for _ in range(3):
            yield a()

    x = list(b())
    assert len(x) == 3
    assert all(inspect.isgenerator(item) for item in x)
    y = list(util.generator_flatten(b()))
    assert len(y) == 6*3
    assert all(type(item) is int for item in y)


def test_secure_filename():
    assert util.secure_filename("My cool movie.mov") == "My_cool_movie.mov"
    assert util.secure_filename("../../../etc/passwd") == "etc_passwd"
    assert secure_filename(u'i contain cool \xfcml\xe4uts.txt') \
        == 'i_contain_cool_umlauts.txt'

def test_serialize_deserialize():
    x = {"I": 3, 20: None, True: "spuzz"}
    assert deserialize.obj(serialize.obj(x)) == x

