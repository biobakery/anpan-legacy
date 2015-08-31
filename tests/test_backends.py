import os
import shutil
from itertools import count

from nose.tools import raises

from anpan import settings, backends
from anpan.util import deserialize

from . import test_models
from .test_models import fakeuser, fakeproject, fakerun

here = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))
settings.backend.args = (db_dir,)

class testLevelDBBackend(object):
    def setup(self):
        self.be = backends.backend().create()

    def teardown(self):
        try:
            self.be.close()
        except:
            pass
        if os.path.exists(db_dir):
            shutil.rmtree(db_dir, True)

    def test_attrs(self):
        assert type(self.be.db) is backends.leveldb.LevelDB
        assert self.be.STATS_RANGE_KEYS == ['user']

    def test_ready(self):
        self.be.close()
        assert self.be.ready() == False
        self.be.open()
        assert self.be.ready() == True

    @raises(backends.leveldb.LevelDBError)
    def test_open_fail(self):
        self.be.open()

    def test_open_success(self):
        self.be.close()
        self.be.open()
        assert type(self.be.stats) is dict
        assert all(k in self.be.stats for k in self.be.STATS_RANGE_KEYS)
        self.be.close()
        self.be.open()
        counter_type = type(count(0))
        assert all(type(self.be.stats[k][1]) is counter_type
                   for k in self.be.STATS_RANGE_KEYS)

    def test_create(self):
        self.teardown()
        self.be = backends.backend()
        assert self.be.ready() == False
        self.be.create()
        assert self.be.ready() == True

    def test_checkpoint(self):
        prev = next(self.be.stats['user'][1])
        self.be.checkpoint()
        ss = deserialize.obj(self.be.db.Get("stats"))
        assert type(ss) is dict
        assert prev+1 == ss['user'][1]
        next(self.be.stats['user'][1])
        self.be.checkpoint()
        after = deserialize.obj(self.be.db.Get("stats"))['user'][1]
        assert after == prev+2
        
    @raises(AttributeError)
    def test_close(self):
        self.be.close()
        self.be.db.Get("stats")

    def test__2step(self):
        container = "user"
        key = "tjefferson"
        val = '{"firstname": "Thomas", "lastname": "Jefferson"}'
        self.be._2step_put(container, key, val)
        assert self.be._2step_get(key) == val

    def test_save_user(self):
        self.be.save_user(fakeuser(pw=True))

    def test_save_project(self):
        self.be.save_project(fakeproject())

    def test_save_run(self):
        self.be.save_run(fakerun())

    def test_load_user(self):
        u = fakeuser(pw=True)
        db = self.be
        db.save_user(u)
        v = db.load_user(u.name)
        for attr in test_models.testUser.attrs:
            assert getattr(v, attr) == getattr(u, attr)

    def test_load_all_users(self):
        u = fakeuser(pw=True)
        db = self.be
        db.save_user(u)
        v = list(db.load_all_users())[0]
        for attr in test_models.testUser.attrs:
            assert getattr(v, attr) == getattr(u, attr)
        
    def test_load_project(self):
        p = fakeproject()
        db = self.be
        db.save_project(p)
        q = db.load_project(p.username, p.name)
        for attr in test_models.testProject.attrs:
            assert getattr(p, attr) == getattr(q, attr)

    def test_load_run(self):
        r = fakerun()
        db = self.be
        db.save_run(r)
        s = db.load_run(r.commit_id, r.projectname, r.username)
        for attr in test_models.testRun.attrs:
            assert getattr(r, attr) == getattr(s, attr)

    
        
        
