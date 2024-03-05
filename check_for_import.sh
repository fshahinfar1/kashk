#! /bin/bash

IMPORT_STRING="from my_type import MyType"

all_files=$(find ./src/ -iname "*.py")
for f in ${all_files[@]}; do
	grep "$IMPORT_STRING" $f &> /dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		# already has imported
		continue
	fi
	grep "MyType" $f &> /dev/null
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "File: $f misses the import"
		# insert import after data_structure
		sed -i "/from data_structure/a $IMPORT_STRING" $f
	fi
done
