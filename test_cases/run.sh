#! /bin/bash

# Load virtual environment if it exists
VENV="../venv/bin/activate"
if [ -f $VENV ]; then
	source $VENV
fi

# List of tests
tests=$(find . -iname "test_*.py")

# Run each test
failures=0
for t in ${tests[@]}; do
	python3 $t 1> /dev/null 2> /tmp/test_stderr
	ret=$?

	if [ $(du /tmp/test_stderr | cut -f 1) -ne 0 ]; then
		printf "\033[31m$t: failed [stderr] \033[0m\n"
		failures=$((failures + 1))
		continue
	fi

	if [ $ret -eq 0 ]; then
		printf "\033[34m$t: passed\033[0m\n"
	else
		printf "\033[31m$t: failed [return code]\033[0m\n"
		failures=$((failures + 1))
	fi

done

echo Number of failed test: $failures
