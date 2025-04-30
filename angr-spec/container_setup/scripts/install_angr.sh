#!/usr/bin/env bash
set -e

venv_name=angr7
_pwd=$PWD
cd

python3 -m venv ~/.virtualenvs/$venv_name
source ~/.virtualenvs/$venv_name/bin/activate

# Install dependencies
pip install -r /home/angr-spec/.container_setup/scripts/requirements.txt

# ✅ Install your local angr repo as an editable package
pip install -e /home/angr-spec/angr

# Optional: create ipython profile
ipython profile create

cd "$_pwd"
