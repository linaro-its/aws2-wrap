"""Setup script for aws2wrap."""

import os
import re

from setuptools import setup

HERE = os.path.abspath(os.path.dirname(__file__))
VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')


def get_version():
    """ Read version from the version file """
    with open(
        os.path.join(
            HERE,
            "aws2wrap",
            "version.py"
        ),
        mode="r",
        encoding="utf-8"
    ) as ver_file:
        init = ver_file.read()
    return VERSION_RE.search(init).group(1)


with open("README.md", mode="r", encoding="utf-8") as fh:
    long_description = fh.read()


setup(
    name="aws2-wrap",
    version=get_version(),
    description="A wrapper for executing a command with AWS CLI v2 and SSO",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/linaro-its/aws2-wrap",
    author="Philip Colmer",
    author_email="it-support@linaro.org",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Environment :: Console',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent'
    ],
    license="GPL-3.0-or-later",
    keywords="aws profile sso assume role",
    packages=[
        "aws2wrap"
    ],
    install_requires=["psutil"],
    entry_points={
        'console_scripts': [
            'aws2-wrap = aws2wrap:main',
        ]
    },
    python_requires=">=3.6",
)
