import os
from multiprocessing import Process

import requests

from anpan import web, settings

devhost = "127.0.0.1"
devport = 43275
devurl = "http://{}:{}/".format(devhost, devport)

def _devserver():
    from anpan import web, settings
    settings.web.host = devhost
    settings.web.port = devport
    settings.web.mount_url = "/"
    settings.debug = False
    web.main()

devprocess = None

def setup_module():
    devprocess = Process(target=_devserver, args=())
    devprocess.start()

def teardown_module():
    if devprocess:
        pid = devprocess.pid
        devprocess.terminate()
        if devprocess.is_alive():
            os.kill(pid, 9)
        devprocess = None


def get(base=devurl, url, *args, **kwargs):
    return requests.get(base+url, *args, **kwargs)

def put(base=devurl, url, *args, **kwargs):
    return requests.put(base+url, *args, **kwargs)

def post(base=devurl, url, *args, **kwargs):
    return requests.post(base+url, *args, **kwargs)

def delete(base=devurl, url, *args, **kwargs):
    return requests.delete(base+url, *args, **kwargs)


def test_state():
    assert False

def test_extract_creds(alt_key):
    assert False

def test_login_reqd(fn):
    assert False

def test_check_permissions(*perms):
    assert False

def test_validate(u, key="user"):
    assert False

def test_lookup(key="user", *args, **kwargs):
    assert False

def test_login():
    assert False

def test_validatetoken():
    assert False

def test_user_get():
    assert False

def test_user_put(username):
    assert False

def test_user_post(username):
    assert False

def test_proj_own_get(projname):
    assert False

def test_proj_other_get(username, projname):
    assert False

def test_hasaccess_get(username, projname, accesstype):
    assert False

def test_proj_put(projname):
    assert False

def test_project_post(projectname):
    assert False

def test_run_get(username, projname, commit_id=None):
    assert False

def test_run_put(username, projname, commit_id):
    assert False

def test_index():
    assert False

