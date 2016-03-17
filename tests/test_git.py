import re
import os
import shutil
import inspect

from nose.tools import raises

from anpan import backends, settings, git

from .test_models import fakeuser, fakeproject

here = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.abspath(os.path.join(here, "..", "testdb"))
settings.backend.args = (db_dir,)

class testRepository(object):

    def setup(self):
        self.db = backends.backend().create()
        self.u = fakeuser(pw=True)
        self.db.save_user(self.u)
        self.p = fakeproject()
        self.u.projects.append(self.p.name)
        self.db.save_project(self.p)
        self.p.deploy()
        self.db.close()


    def teardown(self):
        for path in (self.u.path, db_dir):
            if os.path.exists(path):
                shutil.rmtree(path)


    def test_init(self):
        repo = git.Repository(self.p.path)


    @raises(IOError)
    def test_error_on_no_such_file(self):
        repo = git.Repository("/this/shouldnt/exist")


    def test_validate(self):
        repo = git.Repository(self.p.path)
        assert repo.validate() == True


    def test_commits(self):
        repo = git.Repository(self.p.path)
        commits = repo.commits()
        assert inspect.isgenerator(commits) == True
        commit1 = next(commits)
        # should be a namedtuple
        assert isinstance(commit1, tuple) and hasattr(commit1, "_fields")
        for field in ("id", "author", "date", "msg"):
            # should have these fields
            assert hasattr(commit1, field)


    def test_add(self):
        repo = git.Repository(self.p.path)
        fname = os.path.join(self.p.path, "test.txt")
        with open(fname, 'w') as f:
            print >> f, "Blah"
        repo.add([fname])
        assert os.path.basename(fname) in repo.sh(["git", "status"])[0]


    @raises(ValueError)
    def test_add_fail(self):
        repo = git.Repository(self.p.path)
        fname = "/tmp/test.txt"
        with open(fname, 'w') as f:
            print >> f, "Blah"
        repo.add([fname])
        assert os.path.basename(fname) not in repo.sh(["git", "status"])


    def test_commit(self):
        repo = git.Repository(self.p.path)
        fname = os.path.join(self.p.path, "test.txt")
        with open(fname, 'w') as f:
            print >> f, "Blah"
        msg="add test file"
        author="someuser <dood@place.domain>"
        ci_hash = repo.commit([fname], msg=msg, author=author)
        assert len(ci_hash) == 7
        # ci_hash should only be hexadecimal
        assert len(re.sub(r'[abcdef0-9]', '', ci_hash)) == 0
        ci = next(repo.commits())
        assert ci.id.startswith(ci_hash)
        assert ci.author == author
        assert ci.msg == msg

