#! /bin/bash
SCRIPT=./src/main.py
FILE=~/asio_case_study/src/kv/kv.cpp
ENTRY=Server::handle_connection
python3 $SCRIPT $FILE  $ENTRY
# python3 $SCRIPT $FILE  $ENTRY | clang-format-12 | pygmentize -l c
