from itertools import counter
from base64 import b64encode as b64

import leveldb


from .models import Group, User, Project
from .util import serialize, deserialize



class BaseBackend(object):

    def __init__(self, hasher):
        self.hasher = hasher

    def open(self, create_if_missing=False):
        raise NotImplementedError

    def create(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


    def load_user(self, username):
        raise NotImplementedError

    def load_project(self, username, projectname):
        raise NotImplementedError

    def load_group(self, groupname):
        raise NotImplementedError

    def save_user(self, user_obj):
        raise NotImplementedError

    def save_project(self, project_obj):
        raise NotImplementedError

    def save_group(self, group_obj):
        raise NotImplementedError



class LevelDBBackend(BaseBackend):
    STATS_RANGE_KEYS = ['user', 'group']

    def __init__(self, db_dir, *args, **kws):
        self.db_dir = db_dir
        db = None
        super(self, LevelDBBackend).__init__(*args, **kws)


    def ready(self):
        try:
            db = leveldb.LevelDB(create_if_missing=False, paranoid_checks=True)
            db.Get("stats")
        except:
            return False
        else:
            return True


    def open(self, create_if_missing=False):
        self.db = leveldb.LevelDB(create_if_missing=create_if_missing)
        self.stats = deserialize.obj(self.db.get("stats"))
        for k in self.STATS_RANGE_KEYS:
            self.stats['k'][1] = counter(self.stats['k'][1])
        
        return self


    def create(self):
        self.open(True)
        stats = dict([ (k, (0, 0)) for k in self.STATS_RANGE_KEYS ])
        db.Put("stats", serialize.obj(stats), sync=True)
        
    
    def _2step_get(self, key):
        step_one = self.db.Get(key)
        try:
            step_two = self.db.Get(step_one)
        except KeyError:
            self.db.Delete(key)
            raise
        return step_two

    def _2step_put(self, containerkey, obj_key, val):
        id = next(self.stats[containerkey][1])
        id = container_key+"+_by_id/"+str(id)
        self.db.Put(id, val)
        try:
            self.db.Put(obj_key, id)
        except:
            self.db.Delete(id)
            raise
        return True

    @staticmethod
    def _user_key(username):
        return "user/"+b64(username)

    @staticmethod
    def _project_key(username, projectname):
        return "project/{}/{}".format(b64(username), b64(projectname))
        
    @staticmethod
    def _group_key(groupname):
        return "group/"+b64(groupname)

    def load_user(self, username):
        userblob = self._2step_get(self._user_key(username))
        return User.from_dict(deserialize.obj(userblob))

    def load_project(self, username, projectname):
        # projects are contained within users, so no 2step needed here
        projectblob = self.db.Get(self._project_key(username, projectname))
        return Project.from_dict(deserialize.obj(projectblob))

    def load_group(self, groupname):
        groupblob = self._2step_get(self._group_key)
        return Group.from_dict(deserialize.obj(groupblob))

    def save_user(self, user):
        userblob = serialize.obj(user)
        return self._2step_put("user", self._user_key(user.name), userblob)

    def save_project(self, project):
        projectblob = serialize.obj(project)
        return self.db.Put(self._project_fmt(project.username, project.name),
                           projectblob)

    def save_group(self, group):
        groupblob = serialize.obj(group)
        return self._2step_put("group", self._group_key(group.name), groupblob)
        
