import os

from .util import sh, cd, touch

class Repository(object):

    """Encapsulates a git repository"""

    def __init__(self, path):
        """Initialize a git repository object. DOES NOT EXECUTE ``git init``.

        :param path: The filesystem path of the git repository.

        """

        self.path = path
        self.validate()


    def validate(self):
        """
        Ensure that the git repository is ready to go.
        """
        
        if not os.path.isdir(self.path):
            raise IOError("Path does not exist: "+self.path)

        
    def sh(self, *args, **kwargs):
        """Wrapper for shell commands. ``sh`` changes directory to the repo
        path, executes the shell command, and changes directory pack
        to the previous directory. All arguments are passed to
        subprocess.Popen.

        """

        here = os.getcwd()
        cd(self.path)
        try:
            ret = sh(*args, **kwargs)
        finally:
            cd(here)
        return ret

