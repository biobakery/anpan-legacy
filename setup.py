
from setuptools import setup, find_packages

setup(
    name='anpan',
    version='0.0.1',
    description='AnADAMA Put on A Network',
    packages=find_packages(exclude=['ez_setup', 'tests', 'tests.*']),
    zip_safe=False,
    install_requires=[
        'nose>=1.3.0',
        'python-dateutil>=2.2',
        'bottle>=0.10',
        # doit, six, networkx, etc should come with anadama
        'anadama',
        'anadama_workflows',
    ],
    dependency_links=[
        'git+https://bitbucket.org/biobakery/anadama.git@master#egg=anadama-0.0.1', 
        'git+https://bitbucket.org/biobakery/anadama_workflows.git@master#egg=anadama_workflows-0.0.1',

    ],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha"
    ],
    entry_points= {
        'console_scripts': [
            'anpan-email-validate  = anpan.email.cli:main',
            'anpan                 = anpan.automated.cli:main',
        ],
    }
)
