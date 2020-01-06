from setuptools import setup

setup(
    name="aws2-wrap",
    version="0.1.0",
    description="A wrapper for executing a command with AWS CLI v2 and SSO",
    url="https://github.com/linaro-its/aws2-wrap",
    author="Philip Colmer",
    author_email="it-support@linaro.org",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords="aws profile sso assume role",
    install_requires=[],
    entry_points={
        'console_scripts': [
            'aws2-wrap = aws2wrap:main',
        ]
    }
)