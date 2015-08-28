import os
import sys
import logging
import getpass
import optparse

from . import settings, models, password
from .util import stdin_open, serialize


BANNER = "AnPAN command line interface"

def print_help(*args):
    print >> sys.stderr, BANNER
    print >> sys.stderr, "Available Subcommands:"
    for key in subcommand_map.keys():
        if key.startswith('-'):
            continue
        print >> sys.stderr, "\t "+key


def validate(obj):
    if True != obj.validate() or len(obj.validation_errors) > 1:
        msg = "Error when creating {} ".format(str(obj))
        print >> sys.stderr, msg
        for err in obj.validation_errors:
            print >> sys.stderr, err
        sys.exit(1)
    return True


def has_access(requestor_name, project_owner_name, projectname):
    db = settings.backend.open()
    p = db.load_project(project_owner_name, projectname)
    if requestor_name == p.username:
        return "write"
    elif requestor_name in p.write_users:
        return "write"
    elif p.is_public:
        return "read"
    elif requestor_name in p.read_users:
        return "read"
    return False


##########
# Commands

def initdb_cmd(argv):
    HELP = "Initialize anpan database"
    parser = optparse.OptionParser(option_list=[], usage=HELP)
    parser.parse_args(args=argv)
    settings.backend().create()
    if not os.path.isdir(settings.repository_root):
        os.mkdir(settings.repository_root)
    print "Database setup complete."


def users_cmd(argv):
    HELP = """%prog print serialized users, one per line
    %prog [options] [<username> [...]]"""
    parser = optparse.OptionParser(option_list=[
        optparse.make_option('-j', '--just', dest="attr", default=None,
                            help="Only print this one attribute")
    ], usage=HELP)
    opts, args = parser.parse_args(args=argv)

    db = settings.backend().open()
    if not args:
        users = db.load_all_users()
    else:
        users = iter(db.load_user(n) for n in args)

    if opts.attr:
        def _print(u):
            print serialize.obj(getattr(u, opts.attr))
    else:
        def _print(u):
            print serialize.obj(u)

    for user in users:
        _print(user)
        

def projects_cmd(argv):
    HELP = """%prog print serialized projects, one per line
    %prog [<username>/<projectname> [...]]"""
    parser = optparse.OptionParser(option_list=[
        optparse.make_option('-j', '--just', dest="attr", default=None,
                            help="Only print this one attribute")
    ], usage=HELP)
    opts, args = parser.parse_args(args=argv)

    db = settings.backend().open()
    projects = iter(db.load_project(*spec.split("/")) for spec in args )

    if opts.attr:
        def _print(p):
            print serialize.obj(getattr(p, opts.attr))
    else:
        def _print(p):
            print serialize.obj(p)

    for p in projects:
        _print(p)


def runs_cmd(argv):
    HELP = """%prog print serialized run
    %prog <username> <projectname> <commit_id>"""
    parser = optparse.OptionParser(option_list=[], usage=HELP)
    _, args = parser.parse_args(args=argv)

    if len(args) < 3:
        parser.print_usage()
        sys.exit(1)

    username, projectname, commit_id = args
    db = settings.backend().open()
    run = db.load_run(commit_id, projectname, username)
    print serialize.obj(run)



def createuser_cmd(argv):
    HELP = """%prog - Create anpan user
    %prog [options] <username> [<username> [...]]"""
    
    options = [
        optparse.make_option("-p", "--permission", dest="perms",
                             action="append", default=[],
                             help="Set permissions for new user")
    ]

    parser = optparse.OptionParser(option_list=options, usage=HELP)
    opts, args = parser.parse_args(args=argv)

    db = settings.backend().open()
    for username in args:
        user = models.User(os.path.join(settings.repository_root,
                                        username))
        raw_pw = getpass.getpass("Password for `{}'".format(username))
        hasher = password.hasher_map[None]
        user.set_password(raw_pw, hasher)
        for perm in opts.perms:
            user.permissions[perm] = True
        db.save_user(user)
        print "Completed user setup for `{}'".format(username)


def createproject_cmd(argv):
    HELP = """%prog - Create anpan project
    %prog [options] <username> <projectname> <pipeline_name> [<optional_pipeline> [...]]"""
    
    options = [
        optparse.make_option(
            "-r", "--read", dest="read_users",
            action="append", default=[],
            help="Add this user as read access to the project"),
        optparse.make_option(
            "-w", "--write", dest="write_users",
            action="append", default=[],
            help="Add this user as write access to the project"),
        optparse.make_option(
            "-f", "--from-file", dest="from_file",
            action="store", default=None,
            help=("Add permissions from this file, one per line in "
                  "the format of 'username:permission' e.g. 'quux:read'. "
                  "Use - for stdin")),
        optparse.make_option(
            "-p", "--public", dest="is_public",
            action="store_true", default=False,
            help="Make this project public; readable by everyone"),
    ]

    parser = optparse.OptionParser(option_list=options, usage=HELP)
    opts, args = parser.parse_args(args=argv)


    
    username, projectname, pipename = args[:3]
    opt_pipelines = args[3:]

    if opts.from_file is not None:
        perm_map = {"write": opts.write_users, "read": opts.read_users}
        stdin_msg = "Reading user permissions from stdin"
        with stdin_open(opts.from_file, 'r', stdin_msg=stdin_msg) as f:
            for line in f:
                username, perm = f.strip().split(":")
                perm_map[perm].append(username)

    db = settings.backend().open()
    u = db.load_user(username)
    u.projects.append(projectname)
    p = models.Project(projectname, username,
                       main_pipeline=pipename,
                       optional_pipelines=opt_pipelines,
                       read_users=opts.read_users,
                       write_users=opts.write_users,
                       is_public=opts.is_public,
                       ensure_filestructure=False)
    validated = validate(p)
    if validated:
        p.deploy()
        db.save_project(p)
    

def modifyproject_cmd(argv):
    HELP = """%prog - Modify anpan project
    %prog [options] <username> <projectname>"""
    
    options = [
        optparse.make_option(
            "-r", "--read", dest="read_users",
            action="append", default=[],
            help="Add this user as read access to the project"),
        optparse.make_option(
            "-w", "--write", dest="write_users",
            action="append", default=[],
            help="Add this user as write access to the project"),
        optparse.make_option(
            "-f", "--from-file", dest="from_file",
            action="store", default=None,
            help=("Add permissions from this file, one per line in "
                  "the format of 'username:permission' e.g. 'quux:read'. "
                  "Use - for stdin")),
        optparse.make_option(
            "-p", "--public", dest="is_public",
            action="store_true", default=False,
            help="Make this project public; readable by everyone"),
    ]

    parser = optparse.OptionParser(option_list=options, usage=HELP)
    opts, args = parser.parse_args(args=argv)
    if len(args) < 2:
        parser.print_usage()
        sys.exit(1)

    username, projectname = args

    if opts.from_file is not None:
        perm_map = {"write": opts.write_users, "read": opts.read_users}
        stdin_msg = "Reading user permissions from stdin"
        with stdin_open(opts.from_file, 'r', stdin_msg=stdin_msg) as f:
            for line in f:
                username, perm = f.strip().split(":")
                perm_map[perm].append(username)

    db = settings.backend().open()
    try:
        p = db.load_project(args[0])
    except KeyError:
        print >> sys.stderr, "Project `{}/{}'does not exist: ".format(args)
        sys.exit(1)

    p.is_public = opts.is_public
    p.read_users = opts.read_users
    p.write_users = opts.write_users

    validated = validate(p)
    if validated:
        if not p.deployed():
            p.deploy()
        db.save_project(p)


def createrun_cmd(argv):
    HELP = """%prog - Create/modify anpan run
    %prog [options] <username> <projectname> <commit_id>"""
    
    options = [
        optparse.make_option(
            "-s", "--exit_status", dest="exit_status",
            action="store", default=None,
            help="Store run with this exit status"),
        optparse.make_option(
            "-f", "--log-file", dest="log_file",
            action="store", default=None,
            help=("Location of anadama log file.Use - for stdin")),
    ]

    parser = optparse.OptionParser(option_list=options, usage=HELP)
    opts, args = parser.parse_args(args=argv)
    if len(args) < 3:
        parser.print_usage()
        sys.exit(1)

    if opts.log_file:
        stdin_msg = "Reading log file from stdin"
        with stdin_open(opts.log_file, 'r', stdin_msg=stdin_msg) as f:
            opts.log_file = f.read()
        
    username, projname, commit_id = args
    db = settings.backend().open()
    try:
        run = db.load_run(commit_id, projname, username)
        run.exit_status = opts.exit_status
        run.log = opts.log_file
    except KeyError:
        run = models.Run(commit_id, projname, username, None,
                         opts.exit_status, opts.log_file)

    db.save_run(run)
    

def hasaccess_cmd(argv):
    class exits:
        write_access = 10
        read_access = 11

    HELP="requestor project_owner, project"
    if len(argv) < 3:
        print >> sys.stderr, HELP
        sys.exit(1)

    requestor, project_owner, project = argv
    access = has_access(requestor, project_owner, project)
    if access == "write":
        sys.exit(exits.write_access)
    elif access == "read":
        sys.exit(exits.read_access)
    else:
        sys.exit(0)


def authkey_cmd(argv):
    HELP = """%prog - create valid auth key for user\n    %prog <username>"""
    parser = optparse.OptionParser(option_list=[], usage=HELP)
    _, args = parser.parse_args(args=argv)
    
    if not args:
        parser.print_usage()
        sys.exit(1)

    username = args[0]

    db = settings.backend().open()
    u = db.load_user(username)
    token, create_time = password.token(u.password)
    u.auth_tokens[token] = create_time
    db.save_user(u)
    print token
    


subcommand_map = {
    "--help": print_help,
    "-h": print_help,
    "help": print_help,
    "initdb": initdb_cmd,
    "users": users_cmd,
    "projects": projects_cmd,
    "runs": runs_cmd,
    "createuser": createuser_cmd,
    "createproject": createproject_cmd,
    "modifyproject": modifyproject_cmd,
    "createrun": createrun_cmd,
    "hasaccess": hasaccess_cmd,
    "authkey": authkey_cmd,
}


def main(argv=sys.argv):
    if len(argv) < 2:
        print_help()
        return 1

    subcommand = argv[1]
    if subcommand not in subcommand_map:
        print >> sys.stderr, "`%s' is not a recognized command. Try `help'"%(
            subcommand)
        return 1
    else:
        logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
        return subcommand_map[subcommand](argv[2:])


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
