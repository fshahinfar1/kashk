#! /bin/bash

# If there is a virtual environment directory, enable it
if [ -d ./venv/ ]; then
	source ./venv/bin/activate
fi
CURDIR=$(dirname $0)
SCRIPT=$CURDIR/src/main.py
CASE_STUDY_DIR=$HOME/auto_bpf_offload/auto_bpf_offload_case_study

# FILE=$CASE_STUDY_DIR/src/kv/kv.cpp

# FILE=$CASE_STUDY_DIR/src/lookup/lookup.cpp
# ENTRY=Server::handle_connection

# FILE=$CASE_STUDY_DIR/src/twt/twt.cpp
# ENTRY=WebServer::process_socket

FILE=$CASE_STUDY_DIR/src/twt_c/twt_c.c
ENTRY=handle_connection

# FILE=$CASE_STUDY_DIR/src/memcached/memcached.c
# ENTRY=event_handler
# ARGS="--cflags \-DHAVE_CONFIG_H=1"


python3 $SCRIPT $FILE  $ENTRY $ARGS
# python3 $SCRIPT $FILE  $ENTRY | clang-format-12
# python3 $SCRIPT $FILE  $ENTRY | clang-format-12 | pygmentize -l c
