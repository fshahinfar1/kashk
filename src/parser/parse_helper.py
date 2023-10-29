import re
id_pat = re.compile('[_A-Za-z][_A-Za-z0-9]*')


def is_identifier(name):
    assert isinstance(name, str)
    res = id_pat.fullmatch(name)
    if res is None:
        return False
    return True
