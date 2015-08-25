import os
import sys
import functools

from bottle import (
    get,
    put,
    post,
    abort,
    request,
    redirect
)

from . import db, models, settings
from .util import serialize


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
        username, passwd = map(request.headers.get, ("X-"+USER_KEY,
                                                     "X-"+alt_key))
    elif USER_KEY in request.cookies and alt_key in request.cookies:
        username, passwd = map(request.cookies.get, (USER_KEY, alt_key))
    else:
        abort(401, "Authentication required")

    try:
        user = state().db.load_user(username)
    except Exception as e:
        print >> sys.stderr, str(e)
        abort(401, "Incorrect username or password")
    

def login_reqd(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        authenticated = False
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
        
    if validate != True:
        resp = {"status": 400, "message": "Failed {} validation".format(key),
                "errors": u.validation_errors}
        return abort(400, serialize.obj(resp))
    return True


_lookup_map = {
    "user": lambda: state().db.load_user,
    "group": lambda: state().db.load_group,
    "project": lambda: state().db.load_project
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
        user.auth_tokens.append(auth_token)
        state().db.save_user(user)
        return serialize.obj("status": 200, "message": "Login succeeded",
                             "auth_key": auth_key)


@login_reqd
@get(mount+"user")
def user_get():
    return serialize.obj(request.environ['anpan.user'])


@login_reqd
@put(mount+"user/<username>")
def user_put(username):
    check_permissions("superuser", "user.create")
    u = models.User(os.path.join(settings.repository_root, username))
    for k, v in deseralize.obj(from_fp=request.body):
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
@get(mount+"group/<groupname>")
def group_get(groupname):
    g = lookup(groupname, key="group")
    return serialize.obj(g)

@login_reqd
@put(mount+"group/<groupname>")
def group_put(groupname):
    check_permissions("superuser", "group.create")
    members = deserialize.obj(request.body).get("users", [])
    g = models.Group(groupname, members)
    validate(g, key="group")
    state().db.store_group(g)
    return serialize.obj({"status": 200,
                          "message": "Group `{}' created".format(g.name)})
    

@login_reqd
@post(mount+"group/<groupname>")
def group_post(groupname):
    check_permissions("superuser", "group.modify")
    parms = deserialize.obj(from_fp=request.body)
    g = lookup(groupname, key="group")
    for to_del in parms.get("to_del", []):
        g.users.remove(to_del)
    for to_add in parms.get("to_add", []):
        g.users.add(to_add)
    validate(g, key="group")
    state().db.store_group(g)
    return serialize.obj({"status": 200,
                          "message": "Group `{}' modified".format(g.name)})


@login_reqd
@get(mount+"project/<projname>")
def proj_get(projname):
    user = request.environ['anpan.user']
    return serialize.obj( lookup(user.name, projname, key="project") )


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
        user.projects.append(p.name)
        state().db.save_project(project)
    else:
        abort(500, "Failed to create project "+projname)

    return serialize.obj({"status": 200,
                          "message": "Project `{}' created".format(p.name)})



@get(mount+"")
def index():
    return "Pong"


def main():
    bottle.run(host=settings.web.host, port=settings.web.port,
               debug=settings.debug, reloader=settings.debug)


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

