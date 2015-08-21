import os

from ..util.serialize import SerializableMixin 


class User(SerializableMixin):

    serializable_attrs = ['name', 'path', 'last_updated', 'projects']
    
    def __init__(self, path, repo=None, autopopulate=False):
        self.name = os.path.basename(path)
        self.path = os.path.abspath(path)
        self.projects = list()
        self._last_updated = None

        
    def exists(self):
        raise NotImplementedError

    def __str__(self):
        return "<User '%s'>" % self.name
                                 
    def __repr__(self):
        return "User `{}'".format(self.name)



class Project(SerializableMixin):

    serializable_attrs = ['name', 'user', 'path',
                          'main_pipeline', 'optional_pipelines']
    
    def __init__(self, name, user, autopopulate=False):
        self.name = name
        self.user = user
        self.path = os.path.join(user.path, name)
        self.main_pipeline = str()
        self.optional_pipelines = list()
        
        
    def exists(self):
        raise NotImplementedError


    def __str__(self):
        return "<Project(%s, %s) >" % (self.user.name, self.name)

    def __repr__(self):
        return "Project"

    def __hash__(self):
        return hash(self.path)


