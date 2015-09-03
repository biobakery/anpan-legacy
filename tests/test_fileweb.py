import os
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

from anpan import fileweb, web, settings, backends
from .test_models import fakeuser, fakeproject, fakerun

here = os.path.abspath(os.path.dirname(__file__))
devhost = "127.0.0.1"
devport = 43275
devurl = "http://{}:{}/".format(devhost, devport)
devfurl = "http://{}:{}{}".format(devhost, devport, settings.fileweb.prefix_url)
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))

settings.backend.args = (db_dir,)
settings.web.host = devhost
settings.web.port = devport
settings.web.mount_url = "/"
settings.debug = False
settings.fileweb.host = devhost
settings.fileweb.port = devport+1

def _devserver():
    os.mkdir(settings.repository_root)
    web.main(quiet=True)

def _devfileserver():
    fileweb.main()

devprocess = None
devfileprocess = None

def websetup():
    global devprocess
    global devfileprocess
    devprocess = Process(target=_devserver, args=())
    devprocess.start()
    devfileprocess = Process(target=_devfileserver, args=())
    devfileprocess.start()


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

            
def test_authenticate():
    assert False

def test_has_access_public():
    assert False

def test_has_access():
    assert False

def test_login_reqd():
    assert False

def test_user_proj_path():
    assert False

def test_write_meta_information_to_file():
    assert False

def test_get_or_create_file():
    assert False

def test_save_with_checksum():
    assert False

def test_save_without_checksum():
    assert False

def test_normalize_dest():
    assert False

def test_upload_post():
    assert False

def test_upload_get():
    assert False

def test_rm_post():
    assert False

def test__ls():
    assert False

def test_ls_get():
    assert False

def test_index():
    assert False

def test_main():
    assert False

