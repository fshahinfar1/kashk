#!/bin/bash

set -e
set -x

sudo rmmod kfunc_memcpy || true
pushd ./memcpy_bench/kfunc_memcpy/
make
popd
sudo insmod ./memcpy_bench/kfunc_memcpy/build/kfunc_memcpy.k
sudo ./build/runner -b ./build/memcpy.o
