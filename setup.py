#!/usr/bin/env python

from distutils.core import setup

setup(name='charlotte',
        version='1.0.3',
        description='snort unified alert file processor',
        long_description='Charlotte reads directories full of unified2 files and inserts them into a storage of your choice',
        author='Richard Monk',
        author_email='rmonk@redhat.com',
        packages=['charlotte'],
        scripts=['scripts/charlotte'],
        data_files=[('/etc/init.d', [ 'scripts/init.d/charlotte' ]) ],
    )

