import os
import shutil
from itertools import count

from nose.tools import raises

from anpan import settings
from anpan.util import deserialize

import .models
from .models import fakeuser, fakeproject, fakerun

here = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))
settings.backend = lambda: db.LevelDBBackend(dbdir)

class testLevelDBBackend(object):
    def setup(self):
        self.be = settings.backend()

    def teardown(self):
        if os.path.exists(db_dir):
            shutil.rmtree(db_dir, True)

    def test_attrs(self):
        assert self.be.db == None
        assert self.be.STATS_RANGE_KEYS == ['user']

    def test_ready(self):
        assert self.be.ready() == False
        self.be.open(True)
        assert self.be.ready() == True

    @raises(KeyError)
    def test_open_fail(self):
        self.be.open(False)

    def test_open_success(self):
        self.be.open(True)
        assert type(self.be.stats) is dict
        assert all(k in self.be.stats for k in self.be.STATS_RANGE_KEYS)
        self.be.close()
        self.be.open(False)
        counter_type = type(count(0))
        assert all(type(self.be.stats[k][1]) is counter_type
                   for k in self.be.STATS_RANGE_KEYS)

    def test_create(self):
        assert self.be.ready() == False
        self.be.create()
        assert self.be.ready() == True

    def test_checkpoint(self):
        db = self.be.create()
        exc = None
        try:
            db.Get("stats")
        except KeyError as e:
            exc = e

        assert type(exc) == KeyError
        db.checkpoint()
        assert type(deserialize.obj(db.Get("stats"))) is dict

    @raises(AttributeError)
    def test_close(self):
        self.be.close()
        self.be.db.Get("stats")

    def test__2step(self):
        db = self.be.create()
        container = "presidents"
        key = "tjefferson"
        val = '{"firstname": "Thomas", "lastname": "Jefferson"}'
        db._2step_put(container, key, val)
        assert db._2step_get(key) == val

    def test_save_user(self):
        self.be.create().save_user(fakeuser(pw=True))

    def test_save_project(self):
        self.be.create().save_project(fakeproject())

    def test_save_run(self):
        self.be.create().save_run(fakerun())

    def test_load_user(self):
        u = fakeuser(pw=True)
        db = self.be.create()
        db.save_user(u)
        v = db.load_user(u.name)
        for attr in models.testUser.attrs:
            assert getattr(v, attr) == getattr(u, attr)

    def test_load_all_users(self):
        u = fakeuser(pw=True)
        db = self.be.create()
        db.save_user(u)
        v = list(db.load_all_users())[0]
        for attr in models.testUser.attrs:
            assert getattr(v, attr) == getattr(u, attr)
        
    def test_load_project(self):
        p = fakeproject()
        db = self.be.create()
        db.save_project(p)
        q = db.load_project(p.username, p.name)
        for attr in models.testProject.attrs:
            assert getattr(p, attr) == getattr(q, attr)

    def test_load_run(self):
        r = fakerun()
        db = self.be.create()
        db.save_run(r)
        s = db.load_run(r.commit_id, r.projectname, r.username)
        for attr in models.testRun.attrs:
            assert getattr(r, attr) == getattr(s, attr)

    
        
        
