import os
import sys
import functools

from bottle import (
    run,
    get,
    put,
    post,
    abort,
    request,
    redirect
)

from . import models, settings
from .util import serialize, deserialize


USER_KEY   = "Anpanuser"
PASSWD_KEY = "Anpanpass"
AUTH_KEY   = "Anpanauth"
mount = settings.web.prefix_url


_state = None
def state():
    global _state
    if _state is None:
        _state = GlobalState()
    return _state



class GlobalState(object):
    def __init__(self):
        try:
            self.db = settings.backend().open()
        except Exception as e:
            print >> sys.stderr, str(e)
            print >> sys.stderr, "create database with anpan initdb"
            sys.exit(1)


def extract_creds(alt_key):
    if     "X-"+USER_KEY in request.headers \
       and "X-"+alt_key in request.headers:
        username, alt_obj = map(request.headers.get, ("X-"+USER_KEY,
                                                     "X-"+alt_key))
    elif USER_KEY in request.cookies and alt_key in request.cookies:
        username, alt_obj = map(request.cookies.get, (USER_KEY, alt_key))
    else:
        abort(401, "Authentication required")

    try:
        user = state().db.load_user(username)
    except Exception as e:
        print >> sys.stderr, str(e)
        abort(401, "Incorrect username or password")
    
    return user, alt_obj

# TODO: cache authkeys in memory using a priority queue
def login_reqd(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user, auth_token = extract_creds(AUTH_KEY)
        if True == user.check_token(auth_token):
            request.environ['anpan.user'] = user
            return fn(*args, **kwargs)
        else:
            return redirect(mount+"/login")
    return wrapper

    
def check_permissions(*perms):
    if not any(map(request.environ['anpan.user'].permissions.get, perms)):
        abort(403, "Insufficient permissions")
    return True


def validate(u, key="user"):
    try:
        validated = u.validate()
    except:
        validated = False
        u.validation_errors = []
        
    if validated != True:
        resp = {"status": 400, "message": "Failed {} validation".format(key),
                "errors": u.validation_errors}
        return abort(400, serialize.obj(resp))
    return True


_lookup_map = {
    "user": lambda: state().db.load_user,
    "group": lambda: state().db.load_group,
    "project": lambda: state().db.load_project,
    "run": lambda: state().db.load_run
}

def lookup(key="user", *args, **kwargs):
    lookup_func = _lookup_map[key]()
    try:
        obj = lookup_func(*args, **kwargs)
    except KeyError:
        return abort(404, key+" not found")
    return obj



##########
# Handlers

@get(mount+"login")
def login():
    user, password = extract_creds(alt=PASSWD_KEY)
    auth_token = user.authenticate(password)
    if not auth_token:
        abort(401, "Incorrect username or password")
    else:
        state().db.save_user(user)
        return serialize.obj({"status": 200, "message": "Login succeeded",
                              "auth_key": auth_token})


@login_reqd
@get(mount+"validatetoken")
def validatetoken():
    """Also useful for keeping token alive"""
    return serialize.obj({"status": 200,
                          "message": "Provided auth token is valid"})

@login_reqd
@get(mount+"user")
def user_get():
    return serialize.obj(request.environ['anpan.user'])


@login_reqd
@put(mount+"user/<username>")
def user_put(username):
    check_permissions("superuser", "user.create")
    u = models.User(os.path.join(settings.repository_root, username))
    for k, v in deserialize.obj(from_fp=request.body):
        setattr(u, k, v)

    validate(u, key="user")
    state().db.store_user(u)
    return serialize.obj({"status": 200,
                          "message": "User `{}' created.".format(u.name)})


@login_reqd
@post(mount+"user/<username>")
def user_post(username):
    check_permissions("superuser", "user.modify")
    u = lookup(username, key="user")
    for k,v in deserialize.obj(from_fp=request.body):
        setattr(u, k, v)
    validate(u, key="user")
    state().db.store_user(u)
    return serialize.obj({"status": 200,
                          "message": "User `{}' modified".format(u.name)})
    

@login_reqd
@get(mount+"project/<projname>")
def proj_own_get(projname):
    u = request.environ['anpan.user']
    return serialize.obj( lookup(u.name, projname, key="project") )
    

@login_reqd
@get(mount+"project/<username>/<projname>")
def proj_other_get(username, projname):
    u = request.environ['anpan.user']
    p = lookup(u.name, projname, key="project")
    if p.is_public or u.name == username or u.name in p.read_users:
        return serialize.obj(p)
    else:
        check_permissions("superuser")
        return serialize.obj(p)


@login_reqd
@get(mount+"projectaccess/<username>/<projname>/<accesstype>")
def hasaccess_get(username, projname, accesstype):
    """Answers the question to 'do I have access to foousers/bazproject'?"""
    u = request.environ['anpan.user']
    if accesstype not in ["read", "write"]:
        abort(400, serialize.obj({'status': 400,
                                  "message": "Unsupported access type"}))
    p = lookup(username, projname, key="project")
    _allowed = serialize.obj(
        {"status": 200, "access": accesstype, "allowed": True})
    if u.name == username: # can I modify my own projects? of course
        return _allowed
    if u.name in p.read_users:
        if username in p.write_users:
            return _allowed
        elif accesstype == "read" and username in p.read_users:
            return _allowed
    else: # is in read_users so u can read
        check_permissions("superuser")
        # at this point, the user must be a superuser, so anything is possible
        return _allowed

    return serialize.obj(
        {"status": 200, "access": accesstype, "allowed": False})
        

@login_reqd
@put(mount+"project/<projname>")
def proj_put(projname):
    user = request.environ['anpan.user']
    check_permissions("superuser", "project.create")    
    input_data = deserialize.obj(from_fp=request.body)
    for reqd_key in ["main_pipeline", "optional_pipelines"]:
        if reqd_key not in input_data:
            abort(400, reqd_key+" is a required field")
    p = models.Project(user.name, projname, input_data['main_pipeline'],
                       input_data['optional_pipeline'])
    validate(p, key="project")
    p.deploy()
    if p.deployed():
        state().db.save_project(p)
        user.projects.append(p.name)
    else:
        abort(500, "Failed to create project "+projname)

    return serialize.obj({"status": 200,
                          "message": "Project `{}/{}' created".format(
                              user.name,p.name)})


@login_reqd
@post(mount+"project/<groupname>")
def project_post(projectname):
    user = request.environ['anpan.user']
    parms = deserialize.obj(from_fp=request.body)
    p = lookup(user.name, projectname, key="project")
    p.read_users += set(parms.get("read_users_add", []))
    p.read_users -= set(parms.get("read_users_del", []))
    p.write_users += set(parms.get("write_users_add", []))
    p.write_users -= set(parms.get("write_users_del", []))
    validate(p, key="group")
    state().db.store_project(p)
    return serialize.obj({"status": 200,
                          "message": "Project `{}' modified".format(p.name)})


@login_reqd
@get(mount+"project/<username>/<projname>/runs")
@get(mount+"project/<username>/<projname>/runs/<commit_id>")
def run_get(username, projname, commit_id=None):
    u = request.environ['anpan.user']
    p = lookup("project", username, projname)
    if u.name not in p.read_users:
        msg = "User `{}' is not authorized to read project `{}/{}'"
        abort(403, serialize.obj(
            {"status": 400,
             "message": msg.format(u.name, username, projname)}
        ))
    if commit_id:
        run = lookup("run", commit_id, projname, u.name)
        return serialize.obj(run)
    else:
        return serialize.obj(p.runs)


@login_reqd
@put(mount+"project/<username>/<projname>/runs/<commit_id>")
def run_put(username, projname, commit_id):
    u = request.environ['anpan.user']
    p = lookup(username, projname, key="project")
    if u.name != username or u.name not in p.write_users:
        check_permissions("superuser")
    data = deserialize.obj(from_fp=request.body)
    reporter_data = data.get('reporter_data', None)
    log = data.get("log", None)
    exit_status = data.get("exit_status", None)
    run = models.Run(commit_id, p.name, username, reporter_data,
                     exit_status, log)
    validate(run, key="run")
    p.runs.append(commit_id)
    state().db.save_run(run)
    state().db.save_project(p)
    return serialize.obj({"status": 200,
                          "message": "Run `{}/{}/{}' created".format(
                              username, p.name, commit_id)})
    

@get(mount+"")
def index():
    return "Pong"


def main():
    run(host=settings.web.host, port=settings.web.port,
        debug=settings.debug, reloader=settings.debug)


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

