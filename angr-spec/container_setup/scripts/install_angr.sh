#!/usr/bin/env bash

venv_name=angr8
_pwd=$PWD
cd
export WORKON_HOME="${HOME}/.virtualenvs"

source /usr/share/virtualenvwrapper/virtualenvwrapper.sh
mkvirtualenv $venv_name

workon $venv_name

# We need this angr version, NOT the one in setup.py (was the main branch during
# testing apparently)

pip3 install -r /home/memsight/.container_setup/scripts/requirements.txt

ipython profile create

cd $_pwd
