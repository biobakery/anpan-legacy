import sys
import functools

from bottle import (
    run,
    get,
    put,
    post,
    abort,
    request,

)

from . import models, backends, settings
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
            self.db = backends.backend().open()
        except Exception as e:
            print >> sys.stderr, str(e)
            print >> sys.stderr, "create database with anpan initdb"
            sys.exit(1)
        self.usercache = models.LRUCache()
        self.authcache = models.LRUCache()

def get_or_load_user(username):
    s = state()
    if username in s.usercache:
        return s.usercache[username]
    else:
        try:
            user = s.db.load_user(username)
        except:
            raise
        else:
            s.usercache[username] = user
            return user

def get_or_load_permissions(username, projname):
    s = state()
    if (username, projname) in s.authcache:
        return s.authcache[username, projname]
    else:
        try:
            p = s.db.load_project(username, projname)
        except:
            raise
        else:
            entry = (p.is_public, p.read_users, p.write_users)
            s.authcache[username, projname] = entry
            return entry


def extract_username_alt(alt_key):
    if     "X-"+USER_KEY in request.headers \
       and "X-"+alt_key in request.headers:
        return map(request.headers.get, ("X-"+USER_KEY, "X-"+alt_key))
    elif USER_KEY in request.cookies and alt_key in request.cookies:
        return map(request.cookies.get, (USER_KEY, alt_key))
    else:
        abort(401, "Authentication required")


def extract_creds(alt_key):
    username, alt_obj = extract_username_alt(alt_key)
    try:
        user = get_or_load_user(username)
    except Exception as e:
        print >> sys.stderr, str(e)
        abort(401, "Incorrect username or password")

    return user, alt_obj


def login_reqd(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user, auth_token = extract_creds(AUTH_KEY)
        if True == user.check_token(auth_token):
            request.environ['anpan.user'] = user
            return fn(*args, **kwargs)
        else:
            abort(401, "Authentication required")
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
    "user": lambda: get_or_load_user,
    "group": lambda: state().db.load_group,
    "project": lambda: state().db.load_project,
    "run": lambda: state().db.load_run,
    "permissions": lambda: get_or_load_permissions,
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
    user, password = extract_creds(PASSWD_KEY)
    auth_token = user.authenticate(password)
    if not auth_token:
        abort(401, "Incorrect username or password")
    else:
        state().db.save_user(user)
        return serialize.obj({"status": 200, "message": "Login succeeded",
                              "auth_key": auth_token})


@get(mount+"validatetoken")
@login_reqd
def validatetoken():
    """Also useful for keeping token alive"""
    return serialize.obj({"status": 200,
                          "message": "Provided auth token is valid"})

@get(mount+"user")
@login_reqd
def user_get():
    return serialize.obj(request.environ['anpan.user'])


@put(mount+"user/<username>")
@login_reqd
def user_put(username):
    check_permissions("superuser", "user.create")
    u = models.User(username)
    blob = deserialize.obj(from_fp=request.body)
    if "password" not in blob:
        abort(400, "Password is a required field")
    for k, v in blob.iteritems():
        try:
            setattr(u, k, v)
        except AttributeError:
            pass

    if not u.exists:
        u.deploy()

    validate(u, key="user")
    state().db.save_user(u)
    state().usercache[u.name] = u
    return serialize.obj({"status": 200,
                          "message": "User `{}' created.".format(u.name)})


@post(mount+"user/<username>")
@login_reqd
def user_post(username):
    check_permissions("superuser", "user.modify")
    u = lookup("user", username)
    for k,v in deserialize.obj(from_fp=request.body).iteritems():
        setattr(u, k, v)
    if not u.exists:
        u.deploy()
    validate(u, key="user")
    state().db.save_user(u)
    state().usercache[u.name] = u
    return serialize.obj({"status": 200,
                          "message": "User `{}' modified".format(u.name)})
    

@get(mount+"project/<projname>")
@login_reqd
def proj_own_get(projname):
    u = request.environ['anpan.user']
    return serialize.obj( lookup("project", u.name, projname) )
    

@get(mount+"project/<username>/<projname>")
@login_reqd
def proj_other_get(username, projname):
    u = request.environ['anpan.user']
    p = lookup("project", u.name, projname)
    if p.is_public or u.name == username or u.name in p.read_users:
        return serialize.obj(p)
    else:
        check_permissions("superuser")
        return serialize.obj(p)


@get(mount+"projectaccess/<username>/<projname>/<accesstype>")
def hasaccess_get(username, projname, accesstype):
    """Answers the question to 'do I have access to foousers/bazproject'?"""
    if accesstype not in ["read", "write"]:
        abort(400, serialize.obj({'status': 400,
                                  "message": "Unsupported access type"}))

    packed = lookup("permissions", username, projname)
    is_public, read_users, write_users = packed
    _allowed = serialize.obj(
        {"status": 200, "access": accesstype, "allowed": True})
    if is_public and "read" == accesstype:
        return _allowed

    u, token = extract_creds(AUTH_KEY)
    if u.check_token(token) != True:
        abort(401, "Authentication required")
        
    if u.name in read_users and "read" == accesstype: 
        return _allowed
    elif u.name == username: # can I modify my own projects? of course
        return _allowed
    elif u.name in write_users:
        return _allowed
    else: 
        check_permissions("superuser")
        # at this point, the user must be a superuser, so anything is possible
        return _allowed

    return serialize.obj(
        {"status": 200, "access": accesstype, "allowed": False})
        

@put(mount+"project/<projname>")
@login_reqd
def proj_put(projname):
    user = request.environ['anpan.user']
    db = state().db
    check_permissions("superuser", "project.create")    
    input_data = deserialize.obj(from_fp=request.body)
    for reqd_key in ["main_pipeline", "optional_pipelines"]:
        if reqd_key not in input_data:
            abort(400, reqd_key+" is a required field")
    p = models.Project(projname, user.name, input_data['main_pipeline'],
                       input_data['optional_pipelines'])
    validate(p, key="project")
    p.deploy()
    if p.deployed():
        db.save_project(p)
        user.projects.append(p.name)
        db.save_user(user)
    else:
        abort(500, "Failed to create project "+projname)

    return serialize.obj({"status": 200,
                          "message": "Project `{}/{}' created".format(
                              user.name,p.name)})


@post(mount+"project/<projectname>")
@login_reqd
def project_post(projectname):
    user = request.environ['anpan.user']
    parms = deserialize.obj(from_fp=request.body)
    p = lookup("project", user.name, projectname)
    p.read_users |= set(parms.get("read_users_add", []))
    p.read_users -= set(parms.get("read_users_del", []))
    p.write_users |= set(parms.get("write_users_add", []))
    p.write_users -= set(parms.get("write_users_del", []))
    if 'is_public' in parms:
        p.is_public = bool(parms['is_public'])
    validate(p, key="group")
    state().db.save_project(p)
    entry = (p.is_public, p.read_users, p.write_users)
    state().authcache[p.username, p.name] = entry
    return serialize.obj({"status": 200,
                          "message": "Project `{}' modified".format(p.name)})


@get(mount+"project/<username>/<projname>/runs")
@get(mount+"project/<username>/<projname>/runs/<commit_id>")
@login_reqd
def run_get(username, projname, commit_id=None):
    u = request.environ['anpan.user']
    p = lookup("project", username, projname)
    if not p.is_public and u.name not in p.read_users:
        msg = "User `{}' is not authorized to read project `{}/{}'"
        abort(403, serialize.obj(
            {"status": 403,
             "message": msg.format(u.name, username, projname)}
        ))
    if commit_id:
        run = lookup("run", commit_id, projname, u.name)
        return serialize.obj(run)
    else:
        return serialize.obj(p.runs)


@put(mount+"project/<username>/<projname>/runs/<commit_id>")
@login_reqd
def run_put(username, projname, commit_id):
    u = request.environ['anpan.user']
    p = lookup("project", username, projname)
    if not (u.name == username or u.name not in p.write_users):
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
    
@post(mount+"project/<username>/<projname>/runs/<commit_id>")
@login_reqd
def run_post(username, projname, commit_id):
    u = request.environ['anpan.user']
    p = lookup("project", username, projname)
    if not (u.name == username or u.name not in p.write_users):
        check_permissions("superuser")
    r = lookup("run", username, projname, commit_id)
    data = deserialize.obj(from_fp=request.body)
    for k in ("reporter_data", "exit_status", "log"):
        v = data.get(k, None)
        if v:
            setattr(r, k, v)
    validate(r, key="run")
    state().db.save_run(run)
    if r.commit_id not in p.runs:
        p.runs.append(r.commit_id)
        state().db.save_project(p)
    return serialize.obj({"status": 200,
                          "message": "Run `{}/{}/{}' modified".format(
                              username, p.name, commit_id)})
    

@get(mount+"")
def index():
    return "Pong"


def main(*args, **kwargs):
    run(host=settings.web.host, port=settings.web.port,
        debug=settings.debug, reloader=settings.debug, *args, **kwargs)


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

