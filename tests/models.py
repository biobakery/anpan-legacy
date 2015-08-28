import os
import time

from nose.tools import raises

from anpan import models

class testPermissionsDict(object):
    should_exist = "superuser"
    shouldnt_exist = "fooquux"

    def setUp(self):
        self.d = models.PermissionsDict()

    def test_has_known_permissions(self):
        assert hasattr(self.d, "known_permissions")

    def test_known_permissions_is_set(self):
        assert type(self.d.known_permissions) is set

    def test_known_permissions_contains_something(self):
        assert len(self.d.known_permissions) > 1

    def test_set_should_work(self):
        self.d[self.should_exist] = True

    @raises(ValueError)
    def test_set_shouldnt_work(self):
        self.d[self.shouldnt_exist] = True

    def test_get_should_work(self):
        self.test_set_should_work()
        assert self.d[self.should_work] == True
        
    def test_get_shouldnt_work(self):
        try:
            self.test_set_shouldnt_work()
        except ValueError:
            assert self.shouldnt_work not in self.d

    def test_modify(self):
        self.test_get_should_work()
        self.d[self.should_work] = False
        assert self.d[self.should_work] == False


def fakeuser(pw=None):
    u = models.User("foobaz")
    if pw:
        u.set_password("somepass", password.hash)
    return u        

        
class testUser(object):

    attrs = ("name", "projects", "ssh_public_keys",
             "_password", "auth_tokens", "permissions", "max_token_age")

    types = (str, list, list, str, dict, models.PermissionsDict, int)

    def setup(self):
        self.u = fakeuser()

    def teardown(self):
        if os.path.exists(self.u.path):
            os.rmdir(self.u.path)

    def test_attrs(self):
        for attr in self.attrs:
            assert hasattr(self.u, attr)

    def test_attr_types(self):
        for attr, t in zip(self.attrs, self.types):
            assert type(getattr(self.u, attr)) is t

    def test_deploy(self):
        ret = self.u.deploy()
        assert os.path.isdir(self.u.path)
        assert type(ret) is models.User

    def test_deployed(self):
        self.u.deploy()
        assert self.u.deployed() == True
        
    def test_exists(self)
        self.u.deploy()
        assert self.u.exists() == True

    def test_undeploy(self):
        self.u.deploy()
        self.u.undeploy()
        assert not os.path.isdir(self.u.path)

    def test_validate_success(self):
        self.u.deploy()
        assert self.u.validate() == True
        assert len(self.u.validation_errors) == 0

    def test_validate_fail(self):
        assert self.u.validate() == False
        assert len(self.u.validation_errors) > 0

    def test_getpassword(self):
        assert self.u.password == None

    @raises(Exception)
    def test_setpassword(self):
        self.u.password = "foobaz"

    def test_set_password_func(self):
        from anpan import password
        ret = self.u.set_password("somepass", password.hash)
        assert type(ret) is models.User

    def setpass(self, pw):
        from anpan import password
        self.u.set_password(pw, password.hash)
        

    def test_authenticate_success(self):
        pw = "somepass"
        prev = len(self.u.auth_tokens)
        self.setpass(pw)
        ret = self.u.authenticate(pw)
        assert bool(ret) == True
        assert type(ret) == str
        assert prev < len(self.u.auth_tokens)
        assert ret in self.u.auth_tokens

    def test_authenticate_fail(self):
        prev = len(self.u.auth_tokens)
        self.setpass("somepass")
        ret = self.u.authenticate("som3pass")
        assert ret == False
        assert prev == len(self.u.auth_tokens)
        assert ret not in self.u.auth_tokens

    def test_purge_old_tokens(self):
        pw = "somepass"
        self.setpass(pw)
        tok = self.u.authenticate(pw)
        self.u.auth_tokens[tok] = time.time()-500-self.u.max_token_age
        n_purged = self.purge_old_tokens()
        assert n_purged > 0
        assert len(self.u.auth_tokens) == 0
        assert tok not in self.u.auth_tokens

    def test_check_token_success(self):
        pw = "somepass"
        self.setpass(pw)
        tok = self.u.authenticate(pw)
        assert self.u.check_token(tok) == True
        newtok = self.u.authenticate(pw)
        self.u.auth_tokens[tok] = time.time()-500-self.u.max_token_age
        assert self.u.check_token(newtok) == False

    def test__custom_serialize(self):
        from anpan import password
        self.setpass("blahpass")
        d = self.u._custom_serialize()
        assert type(d) is dict
        for k in self.attrs:
            assert k in d
        pw = d['password']
        assert type(pw) is str
        assert password.is_hashed(pw)

    def test_from_dict(self):
        from anpan import password
        pw = "quux"
        self.setpass(pw)
        d = self.u._custom_serialize()
        user = models.User.from_dict(d)
        assert all( a==b for a, b in zip(self.u.password, user.password) )
        assert password.is_hashed(user.password) == False
        for attr, t in zip(self.attrs, self.types):
            assert type(getattr(user, attr)) is t
            assert getattr(user, attr) == getattr(self.u, attr)

    def test___str__(self):
        assert self.u.name in str(self.u)

    def test___repr___(self):
        assert self.u.name in repr(self.u)


def fakeproject():
    return models.Project(
        "fooproject", "foouser",
        "anadama_workflows.pipelines:WGSPipeline",
        ["anadama_workflows.pipelines:VizualizationPipeline"],
        read_users=["baruser", "bazuser"], write_users=["quuxuser"],
        is_public=True, ensure_filestructure=False
    )


class testProject(object):

    attrs = ("name", "username", "main_pipeline", "optional_pipelines",
             "read_users", "write_users", "is_public", "runs" )

    types = (str, str, str, list,
             set, set, bool, list)

    def setup(self):
        self.p = fakeproject()

    def teardown(self):
        if self.p.deployed():
            self.p.undeploy()
    
    def test_attrs(self):
        for attr in self.attrs:
            assert hasattr(self.p, attr)

    def test_attr_types(self):
        for attr, t in zip(self.attrs, self.types):
            assert type(getattr(self.p, attr)) is t


    def test_validate_success(self):
        ret = self.p.validate()
        assert ret == True
        assert hasattr(self.p.validation_errors) == True
        assert len(self.p.validation_errors) == 0

    def test_validate_fail(self):
        self.p.main_pipeline = ""
        assert self.p.validate() == False
        assert "must use a main" in self.p.validation_errors[0]
        self.p.main_pipeline = "doesntexist"
        assert self.p.validate() == False
        assert "does not exist" in self.p.validation_errors[0]


    def test_dedupe_users(self):
        self.p.read_users += self.p.write_users
        prev = len(self.p.read_users)
        self.p.dedupe_users()
        assert prev - len(self.p.read_users) == len(self.p.write_users)

    def test_dedupe_users_public(self):
        self.p.is_public = True
        prev = len(self.p.read_users)
        self.p.dedupe_users()
        assert len(self.p.read_users) == 0
        assert len(self.p.read_users) > prev

    def test_deploy(self):
        ret = self.p.deploy()
        assert os.path.isdir(self.p.path)
        assert type(ret) is models.Project

    def test_undeploy(self):
        self.u.deploy()
        self.u.undeploy()
        assert not os.path.isdir(self.u.path)

    def test__custom_serialize(self):
        d = self.p._custom_serialize()
        assert type(d) is dict
        for k in self.attrs:
            assert k in d

    def test_from_dict(self):
        d = self.p._custom_serialize()
        project = models.Project.from_dict(d)
        for attr, t in zip(self.attrs, self.types):
            assert type(getattr(project, attr)) is t
            assert getattr(project, attr) == getattr(self.p, attr)

    def test___str__(self):
        s = str(self.p)
        assert self.p.name in s and self.p.username in s

    
def fakerun():
    return  models.Run("fooproject", "foouser", "6f85762",
                       reporter_data="", exit_status=0, log="")

class testRun(object):

    attrs = ("commit_id", "username", "projectname",
             "reporter_data", "exit_status", "log")

    def setup(self):
        self.r = fakerun()

    def test_attrs(self):
        for attr in self.attrs:
            assert hasattr(self.r, attr)
