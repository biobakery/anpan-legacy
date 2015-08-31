from itertools import count
from base64 import b64encode as b64

import leveldb

from . import settings
from .models import User, Project, Run
from .util import serialize, deserialize, get_counter_state

class BaseBackend(object):

    def open(self, create_if_missing=False):
        raise NotImplementedError

    def create(self):
        raise NotImplementedError

    def checkpoint(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


    def save_user(self, user_obj):
        raise NotImplementedError

    def save_project(self, project_obj):
        raise NotImplementedError

    def save_run(self, run):
        raise NotImplementedError


    def load_user(self, username):
        raise NotImplementedError

    def load_all_users(self):
        raise NotImplementedError

    def load_project(self, username, projectname):
        raise NotImplementedError

    def load_run(self, commit_id, projectname, username):
        raise NotImplementedError


class LevelDBBackend(BaseBackend):
    STATS_RANGE_KEYS = ['user']

    def __init__(self, db_dir, *args, **kws):
        self.db_dir = db_dir
        self.db = None
        super(LevelDBBackend, self).__init__(*args, **kws)


    def ready(self):
        try:
            self.db.Get("stats")
        except:
            return False
        else:
            return True


    def open(self):
        self.db = leveldb.LevelDB(self.db_dir,
                                  create_if_missing=False)
        self.stats = deserialize.obj(self.db.Get("stats"))
        for k in self.STATS_RANGE_KEYS:
            self.stats[k][1] = count(self.stats[k][1])
        return self

    def create(self):
        self.db = leveldb.LevelDB(self.db_dir,
                                  create_if_missing=True,
                                  error_if_exists=True)
        self.stats = dict([ (k, (0, 0)) for k in self.STATS_RANGE_KEYS ])
        self.db.Put("stats", serialize.obj(self.stats), sync=True)
        for k in self.STATS_RANGE_KEYS:
            v = self.stats[k]
            self.stats[k] = (v[0], count(v[1]))
        return self

        
    def checkpoint(self):
        stats = self.stats.copy()
        for k in self.STATS_RANGE_KEYS:
            bot, top = stats[k]
            stats[k] = (bot, get_counter_state(top))
        self.db.Put("stats", serialize.obj(stats))


    def close(self):
        self.checkpoint()
        del self.stats
        del self.db
        self.stats = None
        self.db = None

    
    def _2step_get(self, key):
        step_one = self.db.Get(key)
        try:
            step_two = self.db.Get(step_one)
        except KeyError:
            self.db.Delete(key)
            raise
        return step_two

    def _2step_put(self, containerkey, obj_key, val):
        try:
            id = self.db.Get(obj_key)
            new = False
        except KeyError:
            id = next(self.stats[containerkey][1])
            id = containerkey+"_by_id/"+str(id)
            new = True
        self.db.Put(id, val)
        if new:
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
    def _run_key(commit_id, projectname, username):
        return "run/{}/{}/{}".format(commit_id, b64(username), b64(projectname))


    def save_user(self, user):
        userblob = serialize.obj(user)
        return self._2step_put("user", self._user_key(user.name), userblob)

    def save_project(self, project):
        projectblob = serialize.obj(project)
        return self.db.Put(self._project_key(project.username, project.name),
                           projectblob)

    def save_run(self, run):
        return self.db.Put(
            self._run_key(run.commit_id, run.projectname, run.username),
            serialize.obj({"reporter_data": run.reporter_data,
                           "exit_status": run.exit_status,
                           "log": run.log})
        )


    def load_user(self, username):
        userblob = self._2step_get(self._user_key(username))
        return User.from_dict(deserialize.obj(userblob))

    def load_all_users(self):
        keyvals = self.db.RangeIter(
            key_from="user_by_id/"+str(self.stats['user'][0]),
            key_to="user_by_id/"+str(get_counter_state(self.stats['user'][1])),
            include_value=True)
        for _, v in keyvals:
            yield User.from_dict(deserialize.obj(v))

    def load_project(self, username, projectname):
        # projects are contained within users, so no 2step needed here
        projectblob = self.db.Get(self._project_key(username, projectname))
        return Project.from_dict(deserialize.obj(projectblob))

    def load_run(self, commit_id, projectname, username):
        runblob = self.db.Get(self._run_key(commit_id, projectname, username))
        rundata = deserialize.obj(runblob)
        return Run(commit_id, projectname, username,
                   rundata.get("reporter_data", None),
                   rundata.get("exit_status", None),
                   rundata.get("log", None))


backend_map = {
    None: LevelDBBackend,
    "leveldb": LevelDBBackend
}

def backend(name=None):
    b = backend_map[settings.backend.name]
    return b(*settings.backend.args, **settings.backend.keywords)

