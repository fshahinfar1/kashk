#! /bin/bash
for i in $(seq 100); do
	sudo ./build/runner -C 1 -b ./build/map_lookup.o -r 1
	# sudo ./build/runner -C 1 -b ./build/memcpy.o
	# sudo ./build/runner -b ./build/mov_large_obj_to_map_no_bpf_loop.o -C 1 -r 1 -p prog_1
	sleep 1
done

