#!/bin/sh

tarball="pypy3.9-v7.3.16-linux64.tar.bz2"
pypy_dir="${HOME}/.pypy"

_pwd=$PWD

cd

wget "https://downloads.python.org/pypy/$tarball"

tar xf $tarball
rm -f $tarball
extract_dir=$(basename $tarball '.tar.bz2')

mv $extract_dir $pypy_dir

pypy="${pypy_dir}/bin/pypy"

$pypy -m ensurepip

alias pypy=$(realpath ${HOME}/.pypy/bin/pypy3)

pypy -m pip install -r /home/memsight/.container_setup/scripts/requirements_pypy.txt
