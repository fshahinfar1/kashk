#! /bin/bash
source ./venv/bin/activate
SCRIPT=./src/main.py
# FILE=~/asio_case_study/src/kv/kv.cpp
FILE=~/asio_case_study/src/lookup/lookup.cpp
ENTRY=Server::handle_connection

# FILE=./test_cases/linear_pass.cpp
# ENTRY="main"

python3 $SCRIPT $FILE  $ENTRY
# python3 $SCRIPT $FILE  $ENTRY | clang-format-12
# python3 $SCRIPT $FILE  $ENTRY | clang-format-12 | pygmentize -l c
