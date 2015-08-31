import os
import tempfile

testconfig = """
class foobaz(object):
    chumble = "spuzz"
"""


def test_settings():
    with tempfile.NamedTemporaryFile() as tmp_file:
        print >> tmp_file, testconfig
        tmp_file.seek(0)
        os.environ["ANPAN_SETTINGS_FILE"] = tmp_file.name
        from anpan import settings
        settings.reload()
        assert settings.foobaz.chumble == "spuzz"
        
