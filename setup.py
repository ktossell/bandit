#!/usr/bin/env python
from distutils.core import setup
from distutils.command.install import install
from distutils.command.install_data import install_data
from distutils.dist import Distribution
import glob
import os

class BanditInstallConf(install_data):
    install.sub_commands += [('install_conf', lambda self:True)]

    def run(self):
        self.install_dir = os.path.join(self.root or '/', 'etc')
        self.data_files = self.distribution.conf_files
        install_data.run(self)

class BanditDistribution(Distribution):
    def __init__(self, attrs=None):
        self.conf_files = None
        Distribution.__init__(self, attrs=attrs)

setup(name='bandit',
      version='0.1',
      description='Tool for stopping brute-force attacks using iptables rules and log files',
      author='Ken Tossell',
      author_email='ken@tossell.net',
      url='https://github.com/ktossell/bandit',
      license='GPLv3',
      install_requires=['setuptools', 'pyinotify'],
      packages=['bandit'],
      scripts=['scripts/bandit'],
      conf_files=[
          ('bandit/filters', glob.glob('config/filters/*.py.sample')),
      ],
      include_package_data=True,
      cmdclass={'install_conf': BanditInstallConf},
      distclass=BanditDistribution
  )
