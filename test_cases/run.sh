#! /bin/bash
source ../venv/bin/activate

tests=$(find . -iname "test_*.py")

failures=0
for t in ${tests[@]}; do
	python3 $t &> /dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "$t: passed"
	else
		echo "$t: failed"
		failures=$((failures + 1))
	fi
done

echo Number of failed test: $failures
