import os
import time
import shutil
from io import BytesIO
from multiprocessing import Process

from nose.tools import raises, with_setup

from bottle import(
    tob,
    request,
    HTTPError,
    HTTPResponse
)

import requests

from anpan import settings

here = os.path.abspath(os.path.dirname(__file__))
devhost = "127.0.0.1"
devport = 43275
devurl = "http://{}:{}/".format(devhost, devport)
devfurl = "http://{}:{}{}".format(devhost, devport, settings.fileweb.prefix_url)
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))

settings.repository_root = os.path.abspath(os.path.join(here, "..", "testrepo"))
settings.backend.args = (db_dir,)
settings.web.host = devhost
settings.web.port = devport
settings.web.mount_url = "/"
settings.debug = False
settings.fileweb.host = devhost
settings.fileweb.port = devport+1
settings.fileweb.mount_url = "/files/"

from anpan import fileweb, web, backends
from anpan.util import random_string
from .test_models import fakeuser, fakeproject, fakerun

def _devserver():
    if not os.path.isdir(settings.repository_root):
        os.mkdir(settings.repository_root)
    web.main(quiet=True)

def _devfileserver():
    fileweb.main(quiet=True)

devprocess = None
devfileprocess = None

def websetup():
    global devprocess
    global devfileprocess
    devprocess = Process(target=_devserver, args=())
    devprocess.start()
    devfileprocess = Process(target=_devfileserver, args=())
    devfileprocess.start()
    for _ in range(5):
        try:
            get("")
            fget("")
        except:
            pass
        else:
            return None
        time.sleep(0.25)
    raise Exception("failed to bring up web worker")


def usersetup(start_web=True):
    if web._state:
        web._state.db.close()
        web._state = None
    db = backends.backend().create()
    u = fakeuser(pw=True)
    u.permissions['user.create'] = True
    u.permissions['user.modify'] = True
    db.save_user(u)
    db.close()
    if start_web:
        websetup()

def projsetup(start_web=True):
    usersetup(False)
    db = backends.backend().open()
    p = fakeproject()
    u = db.load_user(p.username)
    u.projects.append(p.name)
    db.save_user(u)
    db.save_project(p)
    db.close()
    if start_web:
        websetup()

def runsetup(start_web=True):
    projsetup(False)
    db = backends.backend().open()
    r = fakerun()
    p = db.load_project(r.username, r.projectname)
    p.runs.append(r.commit_id)
    db.save_project(p)
    db.save_run(r)
    db.close()
    if start_web:
        websetup()
    

def teardown():
    global devprocess
    global devfileprocess
    if devprocess:
        pid = devprocess.pid
        devprocess.terminate()
        if devprocess.is_alive():
            os.kill(pid, 9)
        devprocess = None
    if devfileprocess:
        pid = devfileprocess.pid
        devfileprocess.terminate()
        if devfileprocess.is_alive():
            os.kill(pid, 9)
        devfileprocess = None
    shutil.rmtree(db_dir, True)
    shutil.rmtree(settings.repository_root, True)


def fakerequest(body, cookiekvs, headerkvs):
    request.environ['CONTENT_LENGTH'] = str(len(tob(body)))
    request.environ['wsgi.input'] = BytesIO()
    request.environ['wsgi.input'].write(tob(body))
    request.environ['wsgi.input'].seek(0)
    to_del = []
    for k in request.environ.iterkeys():
        if k.startswith("HTTP_X"):
            to_del.append(k)
    for k in to_del:
        request.environ.pop(k)
    request.cookies.clear()
    if cookiekvs:
        request.cookies.update(cookiekvs)
    if headerkvs:
        for k, v in headerkvs.iteritems():
            request.environ["HTTP_"+k.upper().replace("-", "_")] = v


def get(url, base=devurl, *args, **kwargs):
    return requests.get(base+url, *args, **kwargs)

def post(url, base=devurl, *args, **kwargs):
    return requests.post(base+url, *args, **kwargs)

def fget(url, base=devfurl, *args, **kwargs):
    return requests.get(base+url, *args, **kwargs)

def fpost(url, base=devfurl, *args, **kwargs):
    return requests.post(base+url, *args, **kwargs)


@with_setup(usersetup, teardown)            
def test_authenticate():
    u = fakeuser(pw=True)
    assert fileweb.authenticate(u.name, random_string()) == False
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    assert fileweb.authenticate(u.name, tok) == True


@with_setup(projsetup, teardown)
def test_has_access_public():
    u = fakeuser(pw=True)
    p = fakeproject()
    assert fileweb.has_access_public(u.name, p.name) == p.is_public
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    resp = post("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                            "X-"+web.AUTH_KEY: tok},
                json={"is_public": (not p.is_public)})
    assert fileweb.has_access_public(u.name, p.name) == (not p.is_public)


@with_setup(projsetup, teardown)
def test_has_access():
    u = fakeuser(pw=True)
    p = fakeproject()
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    assert fileweb.has_access(u.name, tok, p.username, p.name, "write") == True
    assert fileweb.has_access("somebodyelse", tok,
                              p.username, p.name, "write") == False
    assert fileweb.has_access(u.name, random_string(),
                              p.username, p.name, "write") == False
    

@with_setup(usersetup, teardown)
def test_login_reqd():
    u = fakeuser(pw=True)
    f = lambda *args, **kws: 12345
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    fakerequest("", None, {"X-"+web.USER_KEY: u.name, "X-"+web.AUTH_KEY: tok})
    assert 12345 == fileweb.login_reqd(f)()

@with_setup(usersetup, teardown)
@raises(HTTPError)
def test_login_reqd_fail():
    f = lambda *args, **kws: 12345
    fileweb.login_reqd(f)()


def test_user_proj_path():
    ans = fileweb.user_proj_path('user/proj/some/file.txt')
    assert ("user", "proj", "some/file.txt") == ans
    ans = fileweb.user_proj_path('/user/proj/some/file.txt')
    assert ("user", "proj", "some/file.txt") == ans

@raises(HTTPError)
def test_user_proj_path_fail_to_few_slashes():
    fileweb.user_proj_path('proj/file.txt')

