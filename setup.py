#! /usr/bin/env python
# -*- coding:utf-8 -*-

""" Install some of the scripts.
Intended to be run on the ssh frontends """

import os
from setuptools import setup, find_packages

PACKAGE = 'iotlabaggregator'


def get_version(package):
    """ Extract package version without importing file
    Importing cause issues with coverage,
        (modules can be removed from sys.modules to prevent this)
    Importing __init__.py triggers importing rest and then requests too

    Inspired from pep8 setup.py
    """
    with open(os.path.join(package, '__init__.py')) as init_fd:
        for line in init_fd:
            if line.startswith('__version__'):
                return eval(line.split('=')[-1])  # pylint:disable=eval-used

SCRIPTS = ['serial_aggregator', 'sniffer_aggregator']


setup(
    name=PACKAGE,
    version=get_version(PACKAGE),
    description='IoT-LAB testbed node connection command-line tools',
    author='IoT-LAB Team',
    author_email='admin@iot-lab.info',
    url='http://www.iot-lab.info',
    download_url='https://github.com/iot-lab/aggregation-tools',
    packages=find_packages(),
    scripts=SCRIPTS,
    classifiers=['Development Status :: 3 - Alpha',
                 'Programming Language :: Python',
                 'Intended Audience :: End Users/Desktop',
                 'Environment :: Console',
                 'Topic :: Utilities', ],
    install_requires=['iotlabcli>=1.4.0'],
)
