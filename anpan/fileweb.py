import os
import sys

from bottle import (
    get,
    post,
    request,
)

from . import settings
from .util import serialize, secure_filename

mount = settings.fileweb.prefix_url

class uploadfile():
    def __init__(self, name, type=None, size=None, not_allowed_msg=''):
        self.name = name
        self.type = type
        self.size = size
        self.not_allowed_msg = not_allowed_msg
        self.url = "data/"+name
        self.delete_url = "delete/"+name
        self.delete_type = "DELETE"


    def get_file(self):
        if self.type != None:
            # POST an image
            if self.type.startswith('image'):
                return {"name": self.name,
                        "type": self.type,
                        "size": self.size, 
                        "url": self.url, 
                        "thumbnailUrl": self.thumbnail_url,
                        "deleteUrl": self.delete_url, 
                        "deleteType": self.delete_type,}
            
            # POST an normal file
            elif self.not_allowed_msg == '':
                return {"name": self.name,
                        "type": self.type,
                        "size": self.size, 
                        "url": self.url, 
                        "deleteUrl": self.delete_url, 
                        "deleteType": self.delete_type,}

            # File type is not allowed
            else:
                return {"error": self.not_allowed_msg,
                        "name": self.name,
                        "type": self.type,
                        "size": self.size,}

        # GET image from disk
        elif self.is_image():
            return {"name": self.name,
                    "size": self.size, 
                    "url": self.url, 
                    "thumbnailUrl": self.thumbnail_url,
                    "deleteUrl": self.delete_url, 
                    "deleteType": self.delete_type,}
        
        # GET normal file from disk
        else:
            return {"name": self.name,
                    "size": self.size, 
                    "url": self.url, 
                    "deleteUrl": self.delete_url, 
                    "deleteType": self.delete_type,}


def gen_file_name(filename):
    """
    If file was exist already, rename it and return a new name
    """

    i = 1
    while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        name, extension = os.path.splitext(filename)
        filename = '%s_%s%s' % (name, str(i), extension)
        i = i + 1

    return filename


@post(mount+"upload")
def upload_post():
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        filename = gen_file_name(filename)
        mimetype = file.content_type


        if not allowed_file(file.filename):
            result = uploadfile(
                name=filename, type=mimetype,
                size=0, not_allowed_msg="Filetype not allowed")
        else:
            # save file to disk
            uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'],
                                              filename)
            file.save(uploaded_file_path)

            # create thumbnail after saving

            # get file size after saving
            size = os.path.getsize(uploaded_file_path)

            # return json for js call back
            result = uploadfile(name=filename, type=mimetype, size=size)

    return serialize.obj({"files": [result.get_file()]})


@post(mount+"rm")
def rm_post():
    to_delete = serialize.obj(from_fp=request.body)['files']
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_thumb_path = os.path.join(app.config['THUMBNAIL_FOLDER'], filename)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)

            if os.path.exists(file_thumb_path):
                os.remove(file_thumb_path)
            
            return serialize.obj({filename: 'True'})
        except:
            return serialize.obj({filename: 'False'})


@get(mount+"ls/<b64name>")
def ls_get():
    pass


@get(mount+"")
def index():
    return "Pong"


def main():
    bottle.run(host=settings.fileweb.host, port=settings.fileweb.port,
               debug=settings.debug, reloader=settings.debug)


if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
