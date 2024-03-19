#!/bin/bash
# set -x
set -e
CURDIR=$(realpath $(dirname $0))
YAML=$1
source $CURDIR/venv/bin/activate
python3 $CURDIR/src/main.py $YAML
# /opt/pypy3/bin/pypy3 $CURDIR/src/main.py $YAML
