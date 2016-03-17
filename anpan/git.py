import os
import re
import collections

from .util import sh
from .util import cd
from .util import touch

Commit = collections.namedtuple('gitoutput',['id','author','date','msg'])

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
        else:
            return True


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

    def add(self,fname = []):
        """This method takes the list fname, assumes that the
        filenames are valid, and executes 'git add'
        on these files."""

        try:
            self.sh(['git', 'add'] + fname)
        except IOError:
            raise ValueError('Invalid file names in ' + str(fname))

    def commit(self,fname = [], msg='msg', author='author'):
        """This method takes the list fname and executes 'git add'
        and 'git commit' on the files, using the arguments listed
        here.  The method then calls 'git log' and searches for
        the comment, and returns the partial hash from the most
        recent commit that matches the msg argument.""" 

        authorstr="'" + (author) + "'"
        msgstr="'" + (msg) + "'"
        prettyformat="'"+'%h|%an <%ae>|%ai|%s'+"'"
        commitcmd = ['git','commit', '--message='+msgstr, 
            '--author='+authorstr ]
        gitlogcmd = ['git','log','--pretty=format:'+prettyformat, 
            '--grep='+msgstr, '--max-count=1']

        self.add(fname)
        self.sh(commitcmd)
        gitlog=str(self.sh(gitlogcmd))
        loglist = gitlog.split('|')
        authorname=(loglist[1].split('<')[0])
        msgplain=(''.join(loglist[3])).strip()

        if (authorname in gitlog) and (msgplain in gitlog):
            ci_hash=loglist[0]
            ci_hash=re.sub(r'[^abcdef0-9]', '', ci_hash) 
        else:
            ci_hash="BADHASH"

        return ci_hash 

    def commits(self):
        """This method returns a generator that includes
        "id", "author", "date", and "msg" as parts of a
        named tuple."""

        prettyformat="'"+'%H|%an <%ae>|%ai|%s'+"'"
        gitlogcmd = ['git','log','--pretty=format:'+ prettyformat]
        gitlog = self.sh(gitlogcmd)
        gitlogstr=str(gitlog)

        gitlogstr=gitlogstr.replace('"','').replace("'","").replace('(','') \
                  .replace(', )','').replace('\\n','|')
        gitloglist=gitlogstr.split('|')

        for i in xrange (0,len(gitloglist),4):
            commit=Commit(gitloglist[i],gitloglist[i+1],gitloglist[i+2],
                   gitloglist[i+3])
            yield commit

