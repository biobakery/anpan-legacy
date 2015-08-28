from cStringIO import StringIO
from contextlib import contextmanager

from anpan import cli

from .models import fakeuser, fakeproject, fakerun

here = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))
settings.backend = lambda: db.LevelDBBackend(dbdir)


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


def test_validate():
    assert False

def test_has_access():
    assert False

def test_initdb_cmd():
    assert False

def test_users_cmd():
    assert False

def test_projects_cmd(argv):
    assert False

def test_runs_cmd(argv):
    assert False

def test_createuser_cmd(argv):
    assert False

def test_createproject_cmd(argv):
    assert False

def test_modifyproject_cmd(argv):
    assert False

def test_createrun_cmd(argv):
    assert False

def test_hasaccess_cmd(argv):
    assert False

def test_authkey_cmd(argv):
    assert False


def check_cmd(args, retcode, out_substr=None, err_substr=None):
    with captured_output() as (out, err):
        assert retcode == cli.main(args)
    if out_substr:
        assert out_substr in out.getvalue()
    if err_substr:
        assert err_substr in err.getvalue()


def test_main():
    yield check_cmd, [], 1, None, "not a"
    yield check_cmd, ["anpan", "foooooqux"], 1, None, "not a"
    yield check_cmd, ["anpan", "help"], 0, None, cli.BANNER
    yield check_cmd, ["fooabzid", "help"], 0, None, cli.BANNER
    yield check_cmd, ["anpan", "--help"], 0, None, "Available Subcommands"
    yield check_cmd, ["anpan", "-h"], 0, None, cli.BANNER
    

