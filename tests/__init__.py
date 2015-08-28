import os
import shutil
from anpan import settings

here = os.path.abspath(os.path.dirname(__file__))
def setUpPackage():
    settings.repository_root = os.path.abspath(
        os.path.join(here, '..', "testrepo")
    )
    os.mkdir(settings.repository_root)

def tearDownPackage():
    shutil.rmtree(settings.repository_root, True)

