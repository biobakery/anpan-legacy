import os

from anadama.loader import PipelineLoader
from butter.commands import setup_repo

from . import password
from .util.serialize import SerializableMixin 

def _validate(success, msg, container):
    if not success:
        container.append(msg)


class PermissionsDict(dict):
    known_permissions = set([
        "superuser",
        "user.create", "user.modify",
        "group.create", "group.modify",
        "project.create"
    ])

    def __setitem__(self, key, val):
        if key not in self.known_permissions:
            raise ValueError("Unknown permission "+key)
        return super(self, PermissionsDict).__setitem__(key, val)


class User(SerializableMixin):

    serializable_attrs = ['name', 'path', 'last_updated', 'projects',
                          'password', 'auth_tokens', 'permissions']
    
    def __init__(self, path, projects=list()):
        self.path = os.path.abspath(path)
        self.name = os.path.basename(path)
        self.projects = projects

        self._password = None
        self.auth_tokens = list()
        self.permissions = PermissionsDict()


    def validate(self):
        # validate username, ensure projects exist
        self.validation_errors = []
        return True # for now


    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        raise Exception("Use set_password instead!")

    #Wish I could use a @property, but need extra args
    def set_password(self, password, hasher, *args, **kws):
        self._password = hasher(password, *args, **kws)
        return self


    def check_token(self, auth_token):
        return auth_token in self.auth_tokens


    def authenticate(self, raw_password):
        if not raw_password or type(raw_password) not in (str, unicode):
            return False
        hasher = password.hasher_map[self.password.algorithm]
        to_cmp = hasher(raw_password, self.password.salt,
                        int(self.password.cost))
        if True == password.compare(to_cmp, self.password):
            return password.token(self.password)
        else:
            return False


    @classmethod
    def from_dict(cls, d):
        user = cls(d['path'], projects=d.get("projects", list()))
        user.auth_tokens = d.get("auth_tokens", list())
        maybe_pw = d.get("password", None)
        if maybe_pw and password.is_hashed(maybe_pw):
            user._password = maybe_pw
        return user


    def exists(self):
        raise NotImplementedError

    def __str__(self):
        return "<User '%s'>" % self.name
                                 
    def __repr__(self):
        return "User `{}'".format(self.name)



class Project(SerializableMixin):

    serializable_attrs = ['name', 'username', 'main_pipeline',
                          'optional_pipelines']
    
    def __init__(self, name, username,
                 main_pipeline=str(), optional_pipelines=list(),
                 ensure_filestructure=False):
        self.name = name
        self.username = username
        self.main_pipeline = main_pipeline
        self.optional_pipelines = optional_pipelines
        
        if ensure_filestructure and not self.deployed():
            self.deploy()


    def validate(self):
        self.validation_errors = v = []
        _validate(bool(self.main_pipeline),
                  "The project must use a main pipeline", v)
        _validate(type(self.optional_pipelines) is list,
                  ("The project must have a (maybe empty) "
                   "list of optional pipelines"), v)
        for pipename in [self.main_pipeline]+self.optional_pipelines:
            _validate(PipelineLoader._import(pipename),
                      "The pipeline `{}' does not exist".format(p), v)

        return len(v) < 1


    def deploy(self):
        # TODO: merge anpan settings with butter settings
        prev_environ = os.environ.copy()
        setup_repo(self.path, self.main_pipelin, self.optional_pipelines)
        os.environ = prev_environ


    @property
    def path(self):
        return os.path.join(settings.repository_root,
                            self.username,
                            self.name)

    def deployed(self):
        return all(map(os.path.isdir, (self.path, self.path+".work")))


    def deploy(self):
        pass
    
    @classmethod
    def from_dict(cls, d):
        project = cls(d['name'], d['username'])
        project.main_pipeline = d.get("main_pipeline", "")
        project.optional_pipelins = d.get("optional_pipeline", list())
        return project


    def __str__(self):
        return "<Project(%s, %s) >" % (self.user.name, self.name)

    def __repr__(self):
        return "Project"

    def __hash__(self):
        return hash(self.path)


class Group(SerializableMixin):

    def __init__(self, name, users=set()):
        self.name = name
        self.users = users


    def validate(self):
        self.validation_errors = []
        return True # for now


    def _custom_serialize(self):
        return {"name": self.name, "users": list(self.users)}


    @classmethod
    def from_dict(cls, d):
        return cls(d['name'], set(d['users']))
