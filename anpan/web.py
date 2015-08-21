import sys

import bottle

from . import db, models, settings




def main():
    bottle.run(host=settings.web.host, port=settings.web.port,
               debug=settings.debug, reloader=settings.debug)


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

