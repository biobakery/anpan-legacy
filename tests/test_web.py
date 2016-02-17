import os
import time
import shutil
from io import BytesIO
from multiprocessing import Process

from bottle import(
    tob,
    request,
    HTTPError,
    HTTPResponse
)

import requests

from anpan import web, settings, backends
from .test_models import fakeuser, fakeproject, fakerun

from nose.tools import raises, with_setup

here = os.path.abspath(os.path.dirname(__file__))
devhost = "127.0.0.1"
devport = 43275
devurl = "http://{}:{}/".format(devhost, devport)
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))

settings.backend.args = (db_dir,)
settings.web.host = devhost
settings.web.port = devport
settings.web.mount_url = "/"
settings.debug = False

def _devserver():
    from anpan import web
    os.mkdir(settings.repository_root)
    web.main(quiet=True)

devprocess = None

def websetup():
    global devprocess
    devprocess = Process(target=_devserver, args=())
    devprocess.start()
    for _ in range(5):
        try:
            get("")
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
    if devprocess:
        pid = devprocess.pid
        devprocess.terminate()
        if devprocess.is_alive():
            os.kill(pid, 9)
        devprocess = None
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

def put(url, base=devurl, *args, **kwargs):
    return requests.put(base+url, *args, **kwargs)

def post(url, base=devurl, *args, **kwargs):
    return requests.post(base+url, *args, **kwargs)

def delete(url, base=devurl, *args, **kwargs):
    return requests.delete(base+url, *args, **kwargs)


@with_setup(None, teardown)
def test_extract_creds():
    db = backends.backend().create()
    u = fakeuser(pw=True)
    pw = u._rawpass
    tok = u.authenticate(pw)
    db.save_user(u)
    db.close()
    fakerequest("", None,
                {"X-"+web.USER_KEY: u.name, "X-"+web.AUTH_KEY: tok})
    a, b = web.extract_creds(web.AUTH_KEY)
    assert u.name == a.name and tok == b
    fakerequest("", {web.USER_KEY: u.name, web.PASSWD_KEY: pw},
                None)
    a, b = web.extract_creds(web.PASSWD_KEY)
    assert u.name == a.name and pw == b
    web.state().db.close()
    web._state = None


@raises(HTTPError)
@with_setup(None, teardown)
def test_extract_creds_unauth():
    db = backends.backend().create()
    u = fakeuser(pw=True)
    pw = u._rawpass
    tok = u.authenticate(pw)
    db.save_user(u)
    db.close()
    fakerequest("", None, {"X-"+web.USER_KEY: u.name})
    web.extract_creds(web.PASSWD_KEY)
    web.state().db.close()
    web._state = None


@raises(HTTPError)
@with_setup(None, teardown)
def test_extract_creds_nouser():
    db = backends.backend().create()
    u = fakeuser(pw=True)
    pw = u._rawpass
    tok = u.authenticate(pw)
    db.save_user(u)
    db.close()
    fakerequest("", None,
                {"X-"+web.USER_KEY: "doesntexist", "X-"+web.AUTH_KEY: tok})
    web.extract_creds(web.PASSWD_KEY)
    web.state().db.close()
    web._state = None
    

@with_setup(None, teardown)
def test_login_reqd():
    u = fakeuser(pw=True)
    f = lambda *args, **kws: 12345
    db = backends.backend().create()
    db.save_user(u)
    tok = next(iter(u.auth_tokens.keys()))
    fakerequest("", None, {"X-"+web.USER_KEY: u.name, "X-"+web.AUTH_KEY: tok})
    db.close()
    assert 12345 == web.login_reqd(f)()
    web.state().db.close()
    web._state = None

    
@raises(HTTPResponse)
def test_login_reqd_redirect():
    u = fakeuser(pw=True)
    f = lambda *args, **kws: 12345
    db = backends.backend().create()
    db.save_user(u)
    db.close()
    web.login_reqd(f)()
    web.state().db.close()
    web._state = None


@with_setup(None, teardown)
def test_check_permissions():
    u = fakeuser(pw=True)
    u.permissions['superuser'] = True
    request.environ['anpan.user'] = u
    assert True == web.check_permissions("superuser")
    

@with_setup(None, teardown)
@raises(HTTPError)
def test_check_permissions_denied():
    u = fakeuser(pw=True)
    u.permissions['superuser'] = False
    request.environ = {'anpan.user': u}
    web.check_permissions("superuser")


@with_setup(usersetup, teardown)
def test_login():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    j = resp.json()
    assert j['status'] == 200
    assert "auth_key" in j

    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: "wrong"})
    assert resp.status_code == 401


@with_setup(usersetup, teardown)
def test_validatetoken():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    resp = get("validatetoken", headers={"X-"+web.USER_KEY: u.name,
                                         "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert 200 == j['status']

@with_setup(usersetup, teardown)
def test_user_get():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    resp = get("user", headers={"X-"+web.USER_KEY: u.name,
                                "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert j['name'] == u.name

@with_setup(usersetup, teardown)
def test_user_put():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    new_user = fakeuser(pw=True)
    new_user._rawpass = "anotherpass"
    new_user.name = "anotheruser"
    d = new_user._custom_serialize()
    d['password'] = new_user._rawpass
    resp = put("user/"+u.name,
               headers={"X-"+web.USER_KEY: u.name,
                        "X-"+web.AUTH_KEY: tok},
               json=d)
    assert resp.status_code == 200 and resp.json()['status'] == 200

    resp = get("login", headers={"X-"+web.USER_KEY: new_user.name,
                                 "X-"+web.PASSWD_KEY: new_user._rawpass})
    tok = resp.json()['auth_key']
    resp = get("user", headers={"X-"+web.USER_KEY: new_user.name,
                                "X-"+web.AUTH_KEY: tok})
    assert resp.json()['name'] == new_user.name


@with_setup(usersetup, teardown)
def test_user_post():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    resp = post("user/"+u.name,
                headers={"X-"+web.USER_KEY: u.name,
                         "X-"+web.AUTH_KEY: tok},
                json={"permissions": {"user.create": True}})
    assert resp.status_code == 200 and resp.json()['status'] == 200

    resp = get("user", headers={"X-"+web.USER_KEY: u.name,
                                "X-"+web.AUTH_KEY: tok})
    assert resp.json()['permissions']['user.create'] == True


@with_setup(projsetup, teardown)
def test_proj_own_get():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    p = fakeproject()
    resp = get("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                           "X-"+web.AUTH_KEY: tok})
    assert resp.status_code == 200
    assert resp.json()['name'] == p.name


@with_setup(projsetup, teardown)
def test_proj_other_get():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    p = fakeproject()
    url = "project/{}/{}".format(u.name, p.name)
    resp = get(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok})
    assert resp.status_code == 200
    assert resp.json()['name'] == p.name


@with_setup(projsetup, teardown)
def test_hasaccess_get():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    p = fakeproject()
    url = "projectaccess/{}/{}/write".format(u.name, p.name)
    resp = get(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert j['access'] == "write" and j['allowed'] == True

    url = "projectaccess/{}/{}/read".format(u.name, p.name)
    resp = get(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert j['access'] == "read" and j['allowed'] == True


@with_setup(projsetup, teardown)
def test_hasaccess_get_public():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    p = fakeproject()
    url = "projectaccess/{}/{}/read".format(u.name, p.name)
    resp = get(url)
    j = resp.json()
    assert j['access'] == "read" and j['allowed'] == True

    resp = post("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                            "X-"+web.AUTH_KEY: tok},
                json={"is_public": False})
    assert resp.status_code == 200
    assert resp.json()['status'] == 200

    url = "projectaccess/{}/{}/read".format(u.name, p.name)
    resp = get(url)
    assert resp.status_code == 401



@with_setup(projsetup, teardown)
def test_proj_put():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    p = fakeproject()
    p.name = "fooooobazit"
    resp = put("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                           "X-"+web.AUTH_KEY: tok},
               json=p._custom_serialize())
    resp = get("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                           "X-"+web.AUTH_KEY: tok})
    assert resp.status_code == 200
    assert resp.json()['name'] == p.name


@with_setup(projsetup, teardown)
def test_project_post():
    u = fakeuser(pw=True)
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    p = fakeproject()
    resp = post("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                            "X-"+web.AUTH_KEY: tok},
                json={"write_users_add": ["citizenfour"]})
    assert resp.status_code == 200
    assert resp.json()['status'] == 200
    resp = get("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                           "X-"+web.AUTH_KEY: tok})
    assert "citizenfour" in resp.json()['write_users']
    assert resp.json()['is_public'] == True
    resp = post("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                            "X-"+web.AUTH_KEY: tok},
                json={"is_public": False})
    assert resp.status_code == 200
    assert resp.json()['status'] == 200
    resp = get("project/"+p.name, headers={"X-"+web.USER_KEY: u.name,
                                           "X-"+web.AUTH_KEY: tok})
    assert resp.status_code == 200
    assert resp.json()['is_public'] == False


@with_setup(runsetup, teardown)
def test_run_get():
    u = fakeuser(pw=True)
    p = fakeproject()
    r = fakerun()
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    url = "project/{}/{}/runs".format(u.name, p.name)
    resp = get(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert "commit_ids" in j
    assert j["commit_ids"] == [r.commit_id]

    url = "project/{}/{}/runs/{}".format(u.name, p.name, r.commit_id)
    resp = get(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert j['commit_id'] == r.commit_id
    

@with_setup(projsetup, teardown)
def test_run_put():
    u = fakeuser(pw=True)
    p = fakeproject()
    resp = get("login", headers={"X-"+web.USER_KEY: u.name,
                                 "X-"+web.PASSWD_KEY: u._rawpass})
    tok = resp.json()['auth_key']
    r = fakerun()
    r.commit_id = "bdb39b8"
    r.log = "some\nstuff\n\n"
    r.exit_status = 0
    url = "project/{}/{}/runs/{}".format(u.name, p.name, r.commit_id)
    resp = put(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok},
               json=r._serializable_attrs)
    assert resp.status_code == 200
    assert resp.json()['status'] == 200

    url = "project/{}/{}/runs/{}".format(u.name, p.name, r.commit_id)
    resp = get(url, headers={"X-"+web.USER_KEY: u.name,
                             "X-"+web.AUTH_KEY: tok})
    j = resp.json()
    assert j['commit_id'] == r.commit_id
    

def test_index():
    pass

