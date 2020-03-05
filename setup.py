#!/usr/bin/env python
# coding: utf-8
"""setup"""
from setuptools import setup

if __name__ == "__main__":
    setup(use_scm_version=True,
          dependency_links=[
              'https://github.com/AutomatedTester/Bugsy/tarball/master#egg=bugsy',
              'https://github.com/MozillaSecurity/autobisect/tarball/bugmon-prep#egg=autobisect',
              'https://github.com/MozillaSecurity/prefpicker/tarball/master#egg=prefpicker',
          ])
