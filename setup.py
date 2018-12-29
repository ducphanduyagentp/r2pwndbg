from setuptools import setup

setup(name='r2pwndbg',
      version='0.1',
      description='My attempt to implement an interface for radare2 that assists exploit development, inspired by @ndaprela\'s work',
      url='http://github.com/ducphanduyagentp/r2pwndbg',
      author='Duc Phan',
      author_email='ddp3945@rit.edu',
      license='GPLv3',
      packages=['r2pwndbg'],
      scripts=['bin/r2pwndbg'],
      zip_safe=False)