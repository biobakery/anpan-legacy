import os
import sys
import shutil
import tempfile
from cStringIO import StringIO
from contextlib import contextmanager

from nose.tools import with_setup
import mock

from anpan import settings, backends
from anpan.util import deserialize, serialize

from .test_models import fakeuser, fakeproject, fakerun

here = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))
settings.backend.args = (db_dir,)
settings.repository_root = os.path.abspath(os.path.join(here, "..", "testrepo"))

from anpan import cli


def check_cmd(cmd, args, retcode, out_substr=None, err_substr=None):
    with capture_output() as (out, err):
        assert retcode == cmd(args)
    if out_substr:
        assert out_substr in out.getvalue() or out_substr == out.getvalue()
    if err_substr:
        assert err_substr in err.getvalue() or err_substr == err.getvalue()

@contextmanager
def capture_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err

def setup_module():
    pass

the_db = None

def reposetup():
    global the_db
    the_db = backends.backend().create()
    if not os.path.isdir(settings.repository_root):
        os.mkdir(settings.repository_root)

def usersetup():
    reposetup()
    the_db.save_user(fakeuser(pw=True))

def projsetup():
    usersetup()
    the_db.save_project(fakeproject())

def runsetup():
    projsetup()
    the_db.save_run(fakerun())

def teardown():
    if the_db.ready():
        the_db.close()
    shutil.rmtree(db_dir, True)
    shutil.rmtree(settings.repository_root, True)



def test_validate():
    pass # already tested by tests.models

@with_setup(projsetup, teardown)
def test_has_access():
    p = fakeproject()
    the_db.close()
    assert "write" == cli.has_access("quuxuser", p.username, p.name)
    assert "read" == cli.has_access("nonexistent", p.username, p.name)
    the_db.open()
    p = the_db.load_project(p.username, p.name)
    p.is_public = False
    p.read_users.add("baruser")
    the_db.save_project(p)
    the_db.close()
    assert False == cli.has_access("nonexistent", p.username, p.name)
    assert "read" == cli.has_access("baruser", p.username, p.name)


@with_setup(None, teardown)
def test_initdb_cmd():
    db = backends.backend()
    assert db.ready() == False
    ret = cli.initdb_cmd([])
    assert bool(ret) == False
    db.open()
    assert db.ready() == True
    assert os.path.isdir(settings.repository_root)


@with_setup(usersetup, teardown)
def test_users_cmd():
    the_db.close()
    name = fakeuser().name
    with capture_output() as (out, err):
        ret = cli.users_cmd([])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    assert deserialize.obj(out.getvalue())['name'] == name

    with capture_output() as (out, err):
        ret = cli.users_cmd([name]*3)
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    for line in out.getvalue().split('\n'):
        if line:
            assert deserialize.obj(line)['name'] == name

    with capture_output() as (out, err):
        ret = cli.users_cmd([name, '-j', 'name'])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    assert out.getvalue().strip() == serialize.obj(name)


@with_setup(projsetup, teardown)
def test_projects_cmd():
    the_db.close()
    proj = fakeproject()
    spec = proj.username + "/" + proj.name
    with capture_output() as (out, err):
        ret = cli.projects_cmd([spec]*3)
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    for line in out.getvalue().strip().split('\n'):
        assert deserialize.obj(line)['name'] == proj.name

    with capture_output() as (out, err):
        ret = cli.projects_cmd([spec, '-j', 'name'])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    assert out.getvalue().strip() == serialize.obj(proj.name)
    

@with_setup(runsetup, teardown)
def test_runs_cmd():
    the_db.close()
    run = fakerun()
    with capture_output() as (out, err):
        ret = cli.runs_cmd([run.username, run.projectname, run.commit_id])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    assert deserialize.obj(out.getvalue())['commit_id'] == run.commit_id

@with_setup(reposetup, teardown)
@mock.patch("getpass.getpass")
def test_createuser_cmd(getpass):
    the_db.close()
    getpass.return_value = "somepass"
    with capture_output() as (out, err):
        ret = cli.createuser_cmd(["someuser"])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    assert "someuser" in out.getvalue()
    the_db.open()
    u = the_db.load_user("someuser")
    assert False != u.authenticate("somepass")

    the_db.close()
    with capture_output() as (out, err):
        ret = cli.createuser_cmd(["someboozer", "someotheruser"])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    output = out.getvalue()
    assert "someboozer" in output and "someotheruser" in output
    the_db.open()
    u = the_db.load_user("someotheruser")
    assert False != u.authenticate("somepass")

    the_db.close()
    with capture_output() as (out, err):
        ret = cli.createuser_cmd(["yetanotheruser", "-p", "superuser"])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    assert "yetanotheruser" in out.getvalue()
    the_db.open()
    u = the_db.load_user("yetanotheruser")
    assert True == u.permissions['superuser']
    
@with_setup(usersetup, teardown)
def test_createproject_cmd():
    the_db.close()
    u = fakeuser()
    p = fakeproject()
    with capture_output() as (out, err):
        ret = cli.createproject_cmd([u.name, p.name, p.main_pipeline])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    the_db.open()
    db_u = the_db.load_user(u.name)
    db_p = the_db.load_project(u.name, p.name)
    assert db_p.name in db_u.projects
    assert p.main_pipeline == db_p.main_pipeline


@with_setup(projsetup, teardown)
def test_modifyproject_cmd():
    the_db.close()
    p = fakeproject()
    with capture_output() as (out, err):
        ret = cli.modifyproject_cmd([p.username, p.name, '-p'])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    the_db.open()
    db_p = the_db.load_project(p.username, p.name)
    assert db_p.is_public == False
    
@with_setup(projsetup, teardown)
def test_createrun_cmd():
    the_db.close()
    r = fakerun()
    logstr = "somelogstuff\nyo\n"
    with tempfile.NamedTemporaryFile() as tmp:
        print >> tmp, logstr
        tmp.seek(0)
        with capture_output() as (out, err):
            ret = cli.createrun_cmd([r.username, r.projectname, r.commit_id,
                                     '-s', '1', '-f', tmp.name])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    the_db.open()
    db_r = the_db.load_run(r.commit_id, r.projectname, r.username)
    assert db_r.exit_status == 1
    assert logstr in db_r.log


@with_setup(projsetup, teardown)
def test_hasaccess_cmd():
    the_db.close()
    p = fakeproject()
    check_cmd(cli.hasaccess_cmd,
              ["quuxuser", p.username, p.name], 10, None, None)
    check_cmd(cli.hasaccess_cmd,
              ["nonexistent", p.username, p.name], 11, None, None)


@with_setup(usersetup, teardown)
def test_authkey_cmd():
    name = fakeuser().name
    the_db.close()
    with capture_output() as (out, err):
        ret = cli.authkey_cmd([name])
    assert bool(ret) == False
    assert bool(err.getvalue().strip()) == False
    the_db.open()
    u = the_db.load_user(name)
    assert out.getvalue().strip() in u.auth_tokens
    

def test_main():
    yield check_cmd, cli.main, [], 1, None, cli.BANNER
    yield check_cmd, cli.main, ["anpan", "foooooqux"], 1, None, "not a"
    yield check_cmd, cli.main, ["anpan", "help"], 0, None, cli.BANNER
    yield check_cmd, cli.main, ["fooabzid", "help"], 0, None, cli.BANNER
    yield check_cmd, cli.main, ["anpan", "--help"], 0, None, "ubcommands"
    yield check_cmd, cli.main, ["anpan", "-h"], 0, None, cli.BANNER
    

