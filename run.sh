#!/bin/bash

pwd
cd tests/malloctest
rm -f *.o
make
cd ../../

# scons build/X86/gem5.opt -j$(nproc)

# --debug-flag=MemoryAccess --debug-file='mem.txt' \
# --l2cache --l2_size=1MB --l2_assoc=16 \
/home/yqy/gem5/tests/malloctest/gen.o | build/X86/gem5.opt \
    configs/example/se.py \
    --caches --l1d_size=128B --l1i_size=128B \
    --mem-size=512MB --pool_ids='0,1;' \
    --cpu-type=X86TimingSimpleCPU \
    --cmd='/home/yqy/gem5/tests/malloctest/graph.o' \
#     configs/example/se.py --caches --l1d_size=1kB --l1i_size=1kB --l2cache --l2_size=16kB --num-l2caches=2 --mem-size=32MB --pool_ids='0,1;0,2' --cpu-type=X86TimingSimpleCPU --num-cpu=2 --cmd='/home/ys/Desktop/gem5/tests/malloctest/hello.o;/home/ys/Desktop/gem5/tests/malloctest/malloctest.o'