#!/bin/bash

pwd
cd tests/malloctest
rm -f *.o
make
cd ../../

scons build/X86/gem5.opt -j$(nproc)

build/X86/gem5.opt \
    --debug-flag=MemoryAccess --debug-file='mem.txt' \
    configs/example/se.py \
    --caches --l1d_size=1kB --l1i_size=1kB \
    --l2cache --l2_size=16kB \
    --num-l2caches=2 --mem-size=32MB --pool_ids='0,1;0,2' \
    --cpu-type=X86TimingSimpleCPU --num-cpu=2 \
    --cmd='/home/yqy/gem5/tests/malloctest/hello.o;/home/yqy/gem5/tests/malloctest/malloctest.o' \

#     configs/example/se.py --caches --l1d_size=1kB --l1i_size=1kB --l2cache --l2_size=16kB --num-l2caches=2 --mem-size=32MB --pool_ids='0,1;0,2' --cpu-type=X86TimingSimpleCPU --num-cpu=2 --cmd='/home/yqy/gem5/tests/malloctest/hello.o;/home/yqy/gem5/tests/malloctest/malloctest.o'