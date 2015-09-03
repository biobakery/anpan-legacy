import os
import sys
import hashlib
import datetime
import functools
from base64 import b64decode as unb64

from bottle import (
    get,
    post,
    request,
    urlquote
)

import requests

from . import settings
from .web import USER_KEY, AUTH_KEY, extract_username_alt
from .util import serialize, deserialize, secure_filename

mount = settings.fileweb.prefix_url

baseurl = "http://{}:{}{}".format(
    settings.web.host, settings.web.port, settings.web.prefix_url)
def authenticate(username, auth_key):
    resp = requests.get(baseurl+"validatetoken", stream=False,
                        headers={"X-"+AUTH_KEY: auth_key,
                                 "X-"+USER_KEY: username})
    return resp.status_code == 200


def has_access_public(username, projname):
    url = baseurl+"projectaccess/{}/{}/{}".format(username, projname,
                                                  accesstype)
    resp = requests.get(url, stream=False)
    if resp.status_code != 200:
        return False
    data = deserialize.obj(from_fp=resp.raw)
    return data['access'] == "read" and data['allowed'] == True
    

def has_access(requestorname, auth_key, username, projname, accesstype):
    url = baseurl+"projectaccess/{}/{}/{}".format(username, projname,
                                                  accesstype)
    resp = requests.get(url, stream=False, headers={"X-"+AUTH_KEY: auth_key,
                                                    "X-"+USER_KEY: username})
    if resp.status_code != 200:
        return False
    data = deserialize.obj(from_fp=resp.raw)
    return data['access'] == accesstype and data['allowed'] == True


def login_reqd(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        username, authkey = extract_username_alt(AUTH_KEY)
        if authenticate(username, authkey) != True:
            abort(401, "Authentication required")
        request.environ['anpan.username'] = username
        request.environ['anpan.authkey'] = authkey
        return fn(*args, **kwargs)
    return wrapper


def user_proj_path(path):
    try:
        if path.startswith("/"):
            _, user, proj, rest = path.split("/", 3)
        else:
            user, proj, rest = path.split("/", 2)
    except:
        abort(404)
    else:
        return user, proj, rest


def write_meta_information_to_file(meta_fname, md5sum, chunk, chunks):
    """Writes meta info about the upload, i.d., md5sum, chunk number ...

    :param meta_fname: file name to write to
    :param md5sum: checksum of all uploaded chunks
    :param chunk: chunk number
    :param chunks: total chunk number
    """
    meta_file = open(meta_fname, 'w')
    if chunk < (chunks - 1):
        upload_meta_data = "status=uploading&chunk=%s&chunks=%s&md5=%s" % (
            chunk,chunks,md5sum)
        try:
            meta_file.write(upload_meta_data)
        finally:
            meta_file.close()
    else:
        # last chunk
        path = meta_file.name
        meta_file.close()
        os.remove(path)


def get_or_create_file(chunk, dst):
    if chunk == 0:
        f = file(dst, 'wb')
    else:
        f = file(dst, 'ab')
    return f


def save_with_checksum(dst, md5chunk, md5total, chunk, chunks):
    """Save application/octet-stream request to file.

    :param dst: the destination filepath
    :param chunk: the chunk number
    :param chunks: the total number of chunks
    :param md5chunk: md5sum of chunk
    :param md5total: md5sum of all currently sent chunks
    """
    md5 = hashlib.md5()
    f = get_or_create_file(chunk, dst)
    buf = request['wsgi.input'].read(1024*128)
    while part:
        md5.update(buf)
        f.write(buf)
        buf = request['wsgi.input'].read(1024*128)

    if md5.hexdigest() != md5chunk:
        f.close()
        os.remove(f.name)
        raise abort(400, "Checksum error")
    else:
        f.close()
        
    write_meta_information_to_file(dst+".meta", md5total, chunk, chunks)

    
def save_without_checksum(dst, chunk):
    f = get_or_create_file(chunk, dst)
    buf = request['wsgi.input'].read(1024*128)
    while buf:
        f.write(part)
        buf = request['wsgi.input'].read(1024*128)
    f.close()
    

def normalize_dest(orig_name, check_access="write"):
    uname, pname, filename = user_proj_path(orig_name)
    myname = request.environ['anpan.username']
    auth_key = request.environ['anpan.authkey']
    if not has_access(myname, auth_key, uname, pname, check_access):
        abort(403, "Unauthorized to write to project {}/{}".format(
            uname, pname))

    path, filename = os.path.split(filename)
    filename = secure_filename(filename)
    dst_path = os.path.join(settings.repository_root, uname, pname, path)
    if not os.path.exists(dst_path):
        abort(404)
    dst = os.path.join(dst_path, filename)
    return dst


@post(mount+"upload/<path:re:.*>")
@login_reqd
def upload_post(path):
    dst = normalize_dest(request.POST.name, check_access="write")
    md5chunk = request.POST.get('md5chunk', False)
    md5total = request.POST.get('md5total', False)
    chunk = int(request.POST.get('chunk', 0))
    chunks = int(request.POST.get('chunks', 0))

    if md5chunk and md5total:
        save_with_checksum(dst, md5chunk, md5total, chunk, chunks)
    else:
        save_without_checksum(dst, chunk, chunks)

    return 'uploaded'


@get(mount+"upload/<path:re:.*>")
@login_reqd
def upload_get(path):
    dst = normalize_dest(request.POST.name, check_access="read")
    if(os.path.exists(dst)):
        f_meta_dst = dst + '.meta'
        if(os.path.exists(f_meta_dst)):
            with open(f_meta_dst, 'r') as f_meta:
                data = f_meta.read()
                return urlquote(data)
        else:
            # meta file deleted
            return urlquote("status=finished")
    else:
        return urlquote("status=unknown")


@post(mount+"rm")
@login_reqd
def rm_post():
    to_delete = serialize.obj(from_fp=request.body)['files']
    dsts = [ normalize_dest(filepath, check_access="write")
             for filepath in to_delete ]
    succeeded = []
    failed = []
    for file_path in dsts:
        try:
            os.remove(file_path)
        except Exception as e:
            failed.append((file_path, str(e)))
        else:
            succeeded.append(file_path)
    return serialize.obj(
        {"status": 200, "succeeded": succeeded, "failed": failed})
                             

def _ls(fname):
    ftype = "dir" if os.path.isdir(fname) else "file"
    s = os.stat(fname)
    size = s.st_size
    lastmodified = datetime.datetime.fromtimestamp(s.st_mtime).isoformat()
    created = datetime.datetime.fromtimestamp(s.st_ctime).isoformat()
    return {"type": ftype, "size": size,
            "created": created, "lastmodified": lastmodified }


@get(mount+"ls/<b64name>")
def ls_get(b64name):
    path = unb64(b64name)
    uname, pname, filename = user_proj_path(path)
    path = os.path.join(settings.repository_root, uname, pname, filename)
    if not os.path.exists(path):
        abort(404)
        
    try:
        username, authkey = extract_username_alt(AUTH_KEY)
    except HTTPError:
        has_permission = has_access_public(uname, pname)
    else:
        has_permission = has_access(username, authkey, uname, pname, "read")

    if not has_permission:
        abort(403, "Unauthorized")

    if os.path.isdir(path):
        return serialize.obj({"status": 200,
                              "results": map(_ls, os.listdir(path))})
    else:
        return serialize.obj({"status": 200,
                              "results": [_ls(path)]})


@get(mount+"")
def index():
    return "Pong"


def main():
    bottle.run(host=settings.fileweb.host, port=settings.fileweb.port,
               debug=settings.debug, reloader=settings.debug)


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
