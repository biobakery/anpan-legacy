import os
import sys
import logging
import getpass
import optparse

from . import db, settings
from .util import stdin_open


BANNER = "AnPAN command line interface"

def print_help(*args):
    print >> sys.stderr, BANNER
    print >> sys.stderr, "Available Subcommands:"
    for key in subcommand_map.keys():
        if key.startswith('-'):
            continue
        print >> sys.stderr, "\t "+key


def initdb_cmd(argv):
    HELP = "Initialize anpan database"
    parser = optparse.OptionParser(option_list=[], usage=HELP)
    parser.parse_args(args=argv)

    settings.backend().create()
    print "Database setup complete."


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



def validate_group(g, groupname, db):
    if True != g.validate():
        print >> sys.stderr, "Error when creating group "+groupname
        for err in g.validation_errors:
            print >> sys.stderr, err
        sys.exit(1)
    else:
        db.save_group(g)
        print "Group `{}' creation complete".format(g.name)


def creategroup_cmd(argv):
    HELP = "%prog - Create anpan group\n    %prog [options] <groupname>"
    
    options = [
        optparse.make_option(
            "-u", "--user", dest="users",
            action="append", default=[],
            help="Add this user to the group"),
        optparse.make_option(
            "-f", "--from-file", dest="from_file",
            action="store", default=None,
            help="Add users from this file, one per line. Use - for stdin")
    ]

    parser = optparse.OptionParser(option_list=options, usage=HELP)
    opts, args = parser.parse_args(args=argv)
    if not args:
        print >> sys.stderr, "No groupname provided"
        parser.print_usage()
        sys.exit(1)

    db = settings.backend().open()
    g = models.Group(args[0])
    for username in opts.users:
        g.users.add(username)

    if opts.from_file is not None:
        stdin_msg = "Reading usernames from stdin"
        with stdin_open(opts.from_file, 'r', stdin_msg=stdin_msg) as f:
            for line in f:
                username = f.strip()
                if username:
                    g.users.add(username)

    return validate_group(g, groupname, db)
    


def modifygroup_cmd(argv):
    HELP = "%prog - Modify anpan group\n    %prog [options] <groupname>"
    
    options = [
        optparse.make_option(
            "-a", "--add", dest="to_add",
            action="append", default=[],
            help=("Add this user to the group. "
                  "Can use this option many times to add more users")),
        optparse.make_option(
            "--add-from-file", dest="add_from_file",
            action="store", default=None,
            help="Add users from this file, one per line. Use - for stdin"),
        optparse.make_option(
            "-r", "--remove", dest="to_del",
            action="append", default=[],
            help=("Remove this user to the group. "
                  "Can use this option many times to remove more users")),
        optparse.make_option(
            "--remove-from-file", dest="del_from_file",
            action="store", default=None,
            help="Remove users from this file, one per line. Use - for stdin")

    ]

    parser = optparse.OptionParser(option_list=options, usage=HELP)
    opts, args = parser.parse_args(args=argv)
    if not args:
        print >> sys.stderr, "No groupname provided"
        parser.print_usage()
        sys.exit(1)

    db = settings.backend().open()
    try:
        g = db.load_group(args[0])
    except KeyError:
        print >> sys.stderr, "Group does not exist: "+args[0]

    mods = (g.users.add, g.users.remove)
    packed = ((opts.to_add, opts.add_from_file),
              (opts.to_del, opts.del_from_file))
    stdin_msg = "Reading usernames from stdin"
    for modfunc, (users, fname) in zip(mods, packed):
        for user in users:
            modfunc(user)
        if fname is not None:
            with stdin_open(fname, 'r', stdin_msg=stdin_msg) as f:
                for line in f:
                    username = f.strip()
                    if username:
                        modfunc(username)

    return validate_group(g, groupname, db)    



        
subcommand_map = {
    "--help": print_help,
    "-h": print_help,
    "help": print_help,
    "initdb": initdb_cmd,
    "createuser": createuser_cmd
    "creategroup": creategroup_cmd,
    "modifygroup": modifygroup_cmd,
}


def main():
    if len(sys.argv) < 2:
        print_help()
        return 1

    subcommand = sys.argv[1]
    if subcommand not in subcommand_map:
        print >> sys.stderr, "`%s' is not a recognized command. Try `help'"%(
            subcommand)
        return 1
    else:
        logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s")
        return subcommand_map[subcommand](sys.argv[2:])


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
