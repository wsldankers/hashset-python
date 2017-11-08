#! /usr/bin/python3

from distutils.core import setup, Extension
import re

with open('debian/changelog') as changelog:
	name, version = re.compile('(\S+) \((\S+)\)').match(changelog.readline()).group(1, 2)

setup(
	name = name,
	version = version,
	ext_modules = [Extension('hashset', ['hashset.c', 'qsort_lr.c'])],
)
