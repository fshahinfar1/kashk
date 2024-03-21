#!/bin/bash
# set -x
set -e
CURDIR=$(realpath $(dirname $0))
YAML=$1
source $CURDIR/venv/bin/activate

PROFILER=0
MAIN_CMD="python3 $CURDIR/src/main.py $YAML"
# python3 $CURDIR/src/main.py $YAML
# /opt/pypy3/bin/pypy3 $CURDIR/src/main.py $YAML

if [ $PROFILER -ne 0 ]; then
	python3 -m scalene \
		--profile-exclude gpu \
		--html --outfile /tmp/perf-report.html \
		$CURDIR/src/main.py --- $YAML
else
	$MAIN_CMD
fi
