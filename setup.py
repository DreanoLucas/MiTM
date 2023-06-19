#!/usr/bin/env python3
"""Script d'instalation du paquet biblio."""
from setuptools import setup
import mitm


setup(
	name="Man In The Middle",
	version=mitm.VERSION,
	description="Paquet pour gérer les Attaques Réseaux",
	packages=["mitm"]
	install_requires=["scapy>=2.5"],
    	python_requires= "~=3.7"
)
