#!/usr/bin/env python

from fridab import __version__
from setuptools import setup
import json
import os

requirements = [
	"frida-tools",
]

setup(
	name="fridab",
	version=__version__,
	description="Afterburner for Frida - Quality of life improvements for frida-tools",
	long_description=open("README.md").read(),
	long_description_content_type="text/markdown",
	author="Dimitris Zervas",
	author_email="dzervas@dzervas.gr",
	url="https://github.com/dzervas/frida-afterburner",
	license="GPLv3",
	install_requires=requirements,
	entry_points={
		"console_scripts": [
			"fridab=fridab:main",
		],
	},
)
