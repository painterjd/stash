# -*- coding: utf-8 -*-
import sys
try:
    from distutils.core import setup
    from setuptools import find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages
else:
    REQUIRES = [
        'colorama', 'keyring', 'requests'
    ]

    setup(
        name='stash',
        version='0.3',
        entry_points = {
            'console_scripts': ['stash=stash.stash:main']
        },
        description='Stash - Put Your Stuff Here',
        license='Apache License 2.0',
        url='github.com/painterjd/stash',
        author='Jamie Painter',
        author_email='jamie.painter@rackspace.com',
        include_package_data=True,
        install_requires=REQUIRES,
        test_suite='stash',
        zip_safe=False,
        data_files=[],
        packages=find_packages(exclude=['tests*', 'stash/tests*'])
    )
