import json

def tsv(file_handle):
    for i, line in enumerate(file_handle):
        cols = line.split('\t')
        if line.strip() == "":
            continue
        if len(cols) < 2:
            raise AttributeError(
                "Improper formatting in file %s - "
                "only %d column(s) found on line %d" % (
                    file_handle.name, len(cols), i)
            )

        yield ( 
            cols[0], 
            [ col.strip() for col in cols[1:] ] 
            )

def obj(s=None, from_fp=None):
    if s:
        return json.loads(s)
    elif from_fp:
        return json.load(from_fp)
