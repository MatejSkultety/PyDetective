from setuptools import setup, find_packages
from setuptools.command.install import install
import os

VERSION = '1.0.0'

class xxxx(install):
        def run(self):
            pass

DESCRIPTION = 'x'
LONG_DESCRIPTION = 'x'

setup(
    name="etheruim",
    version=VERSION,
    author="x",
    author_email="x@gmail.com",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    cmdclass={
        'install': xxxx,
    },
    packages=find_packages(),
    setup_requires=['fernet', 'requests'],
    keywords=[],
    classifiers=[
        "Operating System :: Microsoft :: Windows",
    ]
)

