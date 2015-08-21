import json
import types
from cStringIO import StringIO


class SerializationError(TypeError):
    pass

def _serialize_tsv(data_dict, fp):
    for key, value in data_dict.iteritems():
        if not value:
            continue
        elif isinstance(value, types.StringTypes):
            value = [value]
        elif type(value) in (tuple, list):
            value = [ str(item) for item in value ]
        elif type(value) is bool:
            value = ["true"] if value else ["false"]
        else:
            value = [str(value)]
        
        print >> fp, "\t".join([key]+value)

    return fp


def tsv(data_dict, to_fp=None):
    if to_fp:
        _serialize_tsv(data_dict, fp=to_fp)
        return
    else:
        return _serialize_tsv(data_dict, StringIO()).getvalue()


def _defaultfunc(obj):
    if hasattr(obj, '_serializable_attrs'):
        return obj._serializable_attrs
    elif hasattr(obj, 'isoformat'):
        return obj.isoformat()
        
    raise SerializationError("Unable to serialize object %s" %(obj))
        

def obj(obj, to_fp=None):
    if to_fp:
        return json.dump(obj, to_fp, default=_defaultfunc)
    else:
        return json.dumps(obj, default=_defaultfunc)


class SerializableMixin(object):
    """Mixin that defines a few methods to simplify serializing objects
    """

    serializable_attrs = []

    @property
    def _serializable_attrs(self):
        if hasattr(self, "_custom_serialize"):
            return self._custom_serialize()
        else:
            return dict([
                (key, getattr(self, key))
                for key in self.serializable_attrs
            ])
