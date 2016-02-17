import os
import time
import shutil
from collections import deque

from anadama.loader import PipelineLoader
from butter.commands import setup_repo

from . import password, settings
from .util.serialize import SerializableMixin 

DEFAULT_CACHE_SIZE=1000

def _validate(success, msg, container):
    if not success:
        container.append(msg)


class LRUCache(dict):
    def __init__(self, *args, **kwargs):
        max_size      = kwargs.pop('max_size', DEFAULT_CACHE_SIZE)
        super(LRUCache, self).__init__(*args, **kwargs)
        self.q        = deque([], maxlen=max_size)
        self.max_size = max_size

    def _push(self, k):
        if len(self.q) >= self.max_size:
            old_key = self.q[0]
            if old_key != k and super(LRUCache, self).__contains__(old_key):
                super(LRUCache, self).__delitem__(old_key)
        self.q.append(k)
                
    def __getitem__(self, key):
        val = super(LRUCache, self).__getitem__(key)
        self._push(key)
        return val

    def __setitem__(self, key, val):
        super(LRUCache, self).__setitem__(key, val)
        self._push(key)


class PermissionsDict(dict):
    known_permissions = set([
        "superuser",
        "user.create", "user.modify",
        "project.create"
    ])

    def __setitem__(self, key, val):
        if key not in self.known_permissions:
            raise ValueError("Unknown permission "+key)
        return super(PermissionsDict, self).__setitem__(key, val)


class User(SerializableMixin):

    max_token_age = 60*60*24 # 24 hrs in sec

    def __init__(self, name, projects=list(), ssh_public_keys=list()):
        self.name = name
        self.path = os.path.abspath(
            os.path.join(settings.repository_root, name))
        self.projects = projects
        self.ssh_public_keys = ssh_public_keys

        self._password = None
        self.auth_tokens = dict()
        self.permissions = PermissionsDict()


    def deploy(self):
        if not os.path.isdir(self.path):
            os.mkdir(self.path)
        return self

    def deployed(self):
        return os.path.isdir(self.path)

    exists = property(deployed)

    def undeploy(self):
        os.rmdir(self.path)

    def validate(self):
        # validate username, ensure projects exist
        self.validation_errors = v = []
        _validate(os.path.exists(self.path),
                  "user path does not exist", v)
        return len(v) == 0


    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self.set_password(value)

    def set_password(self, pw_str, hasher=None, *args, **kws):
        if not hasher:
            hasher = password.hasher_map['default']
        elif type(hasher) is str:
            hasher = password.hasher_map[hasher]
        self._password = hasher(pw_str, *args, **kws)
        return self


    def authenticate(self, raw_password):
        if not raw_password or type(raw_password) not in (str, unicode):
            return False
        hasher = password.hasher_map[self.password.algorithm]
        to_cmp = hasher(raw_password, self.password.salt,
                        int(self.password.cost))
        if True == password.compare(to_cmp, self.password):
            token, time = password.token()
            self.auth_tokens[token] = time
            return token
        else:
            return False


    def purge_old_tokens(self):
        to_purge = []
        now = time.time()
        for token, birthdate in self.auth_tokens.iteritems():
            if now-birthdate > self.max_token_age:
                to_purge.append(token)
        for t in to_purge:
            del self.auth_tokens[t]
        return len(to_purge)
            

    def check_token(self, auth_token):
        self.purge_old_tokens()
        present = auth_token in self.auth_tokens
        if present:
            self.auth_tokens[auth_token] = time.time()
        return present


    def _custom_serialize(self):
        return {
            "name": self.name,
            "path": self.path,
            "projects": self.projects,
            "password": password.serialize(self.password),
            "ssh_public_keys": self.ssh_public_keys,
            "auth_tokens": self.auth_tokens,
            "permissions": self.permissions,
            "exists": self.exists
        }


    @classmethod
    def from_dict(cls, d):
        user = cls(d['name'],
                   d.get("projects", list()),
                   d.get("ssh_public_keys", list()))
        if 'path' in d:
            user.path = d['path']
        user.auth_tokens = d.get("auth_tokens", dict())
        maybe_pw = d.get("password", None)
        user.projects = d.get("projects", list())
        user.permissions = PermissionsDict(d.get("permissions", dict()))
        if maybe_pw and password.is_serialized(maybe_pw):
            user._password = password.split(maybe_pw)
        return user


    def __str__(self):
        return "<User '%s'>" % self.name
                                 
    def __repr__(self):
        return "User `{}'".format(self.name)



class Project(SerializableMixin):

    def __init__(self, name, username,
                 main_pipeline=str(), optional_pipelines=list(),
                 read_users=list(), write_users=list(),
                 is_public=False, ensure_filestructure=False):
        self.name = name
        self.username = username
        self.main_pipeline = main_pipeline
        self.optional_pipelines = optional_pipelines
        self.read_users = set(read_users)
        self.write_users = set(write_users)
        self.is_public = bool(is_public)
        self.runs = list()

        if ensure_filestructure and not self.deployed():
            self.deploy()

        self.dedupe_users()


    def validate(self):
        self.validation_errors = v = []
        # TODO: ensure that the deployed pipelines match the model's pipelines
        _validate(bool(self.main_pipeline),
                  "The project must use a main pipeline", v)
        _validate(type(self.optional_pipelines) is list,
                  ("The project must have a (maybe empty) "
                   "list of optional pipelines"), v)
        for pipename in [self.main_pipeline]+self.optional_pipelines:
            try:
                PipelineLoader._import(pipename)
            except:
                _validate(False,
                          "The pipeline `{}' does not exist".format(pipename),
                          v)

        return len(v) == 0


    def dedupe_users(self):
        if self.is_public:
            self.read_users = set([])
        else:
            self.read_users -= self.read_users & self.write_users


    def deploy(self):
        # TODO: merge anpan settings with butter settings
        prev_environ = os.environ.copy()
        setup_repo(self.path, self.main_pipeline, self.optional_pipelines)
        os.environ = prev_environ
        return self


    @property
    def path(self):
        return os.path.join(settings.repository_root,
                            self.username,
                            self.name)

    def deployed(self):
        return all(map(os.path.isdir, (self.path, self.path+".work")))

    exists = deployed

    def undeploy(self):
        shutil.rmtree(self.path, True)
        shutil.rmtree(self.path+".work", True)


    @classmethod
    def from_dict(cls, d):
        project = cls(d['name'], d['username'],
                      read_users=d.get("read_users", list()),
                      write_users=d.get("write_users", list()),
                      is_public=d.get("is_public", False))
        project.main_pipeline = d.get("main_pipeline", "")
        project.optional_pipelines = d.get("optional_pipelines", list())
        project.runs = d.get("runs", list())
        return project


    def _custom_serialize(self):
        self.dedupe_users()
        return {
            "name": self.name,
            "username": self.username,
            "main_pipeline": self.main_pipeline,
            "optional_pipelines": list(self.optional_pipelines),
            "runs": list(self.runs),
            "is_public": bool(self.is_public),
            "read_users": list(self.read_users),
            "write_users": list(self.write_users),
        }


    def __str__(self):
        return "<Project(%s/%s)>" % (self.username, self.name)

    def __repr__(self):
        return "Project"



class Run(SerializableMixin):
    serializable_attrs = ['commit_id', 'username', 'projectname',
                          'reporter_data', 'exit_status', 'log']

    def __init__(self, commit_id, projectname, username,
                 reporter_data=None, exit_status=None, log=None):
        self.commit_id = commit_id
        self.projectname = projectname
        self.username = username
        self.reporter_data = reporter_data
        self.exit_status = exit_status
        self.log = log

    def validate(self):
        self.validation_errors = []
        return True # for now

    def __repr__(self):
        fmt = "Run <{}/{}@{}>"
        return fmt.format(self.username, self.projectname, self.commit_id)


