#!/usr/bin/env python3

"""Script d'instalation du paquet biblio."""
from setuptools import setup
import mitm


setup(
	name="biblio",
	version=mitm.VERSION,
	description="un paquet pour gérer des bibliothèques",
	packages=["biblio"],
	scripts=["bibliodb"]
)
