#! /bin/bash

# Load virtual environment if it exists
VENV="../venv/bin/activate"
if [ -f $VENV ]; then
	source $VENV
fi

# List of tests
tests=$(find . -iname "test_*.py")
count_tests=$(find . -iname "test_*.py" | wc -l)
echo Number of tests $count_tests

main() {
	# Run each test
	failures=0
	for t in ${tests[@]}; do
		python3 $t 1> /dev/null 2> /tmp/test_stderr
		ret=$?

		STDERR=""
		RETCODE=""
		if [ $(du /tmp/test_stderr | cut -f 1) -ne 0 ]; then
			STDERR="[stderr]"
		fi

		if [ $ret -ne 0 ]; then
			RETCODE="[retcode]"
		fi

		if [ -z "$STDERR" -a -z "$RETCODE" ]; then
			printf "\033[34m$t: passed\033[0m\n"
		else
			printf "\033[31m$t: failed $RETCODE $STDERR \033[0m\n"
			failures=$((failures + 1))
		fi

	done

	echo Number of failed test: $failures
}

py_main() {
	CURDIR=$(dirname $0)
	python3 $CURDIR/script.py
}

py_main | tee /tmp/kashk_test_report.txt
