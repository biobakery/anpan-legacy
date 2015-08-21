import os

from . import password
from .util.serialize import SerializableMixin 


class User(SerializableMixin):

    serializable_attrs = ['name', 'path', 'last_updated', 'projects',
                          'password']
    
    def __init__(self, path, backend, projects=list()):
        self.path = os.path.abspath(path)
        self.name = os.path.basename(path)
        self.projects = projects
        self.backend = backend

        self._password = None

    def validate(self):
        # validate username, ensure projects exist
        pass


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


    @classmethod
    def from_dict(cls, d):
        user = cls(d['path'], projects=d.get("projects", list()))
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
    
    def __init__(self, name, username):
        self.name = name
        self.username = username
        self.main_pipeline = str()
        self.optional_pipelines = list()
        
        
    def exists(self):
        raise NotImplementedError


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


    def _custom_serialize(self):
        return {"name": self.name, "users": list(self.users)}


    @classmethod
    def from_dict(cls, d):
        return cls(d['name'], set(d['users']))
