#! /bin/bash
for i in $(seq 1000); do
	sudo ./build/runner -C 0 -b ./build/map_lookup.o -r 1
done

