
from setuptools import setup, find_packages

setup(
    name='anpan',
    version='0.1.0',
    description='AnADAMA Put on A Network',
    packages=find_packages(exclude=['ez_setup', 'tests', 'tests.*']),
    zip_safe=False,
    test_suite="nose.collector",
    install_requires=[
        'nose>=1.3.0',
        'simple-pbkdf2',
        'bottle',
        'leveldb==0.193',
        'butter',
        'anadama',
        'anadama_workflows',
    ],
    dependency_links=[
        'git+https://bitbucket.org/biobakery/butter.git@master#egg=butter-0.0.1',
        'git+https://bitbucket.org/biobakery/anadama.git@master#egg=anadama-0.0.1', 
        'git+https://bitbucket.org/biobakery/anadama_workflows.git@master#egg=anadama_workflows-0.0.1',

    ],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha"
    ],
    entry_points= {
        'console_scripts': [
            'anpan-web     = anpan.web:main',
            'anpan-fileweb = anpan.fileweb:main'
            'anpan         = anpan.cli:main',
        ],
    }
)
