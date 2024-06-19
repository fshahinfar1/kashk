#! /bin/bash
for i in $(seq 1000); do
	sudo ./build/runner -b ./build/map_lookup.o -r 10000
done

