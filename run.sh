#!/bin/bash

pwd
cd tests/malloctest
rm -f *.o
make -j$(nproc)
cd ../../

scons build/X86/gem5.opt -j$(nproc)
 
# --debug-flag=MemoryAccess --debug-file='mem.txt' \

# tests/malloctest/gen.o | \
build/X86/gem5.opt \
    configs/example/se.py \
    --caches --l1d_size=128B --l1i_size=128B \
    --l2cache --l2_size=1MB --l2_assoc=16 \
    --mem-size=512MB --pool_ids='0,1;' \
    --cpu-type=O3CPU \
    --cmd='/home/yqy/gem5/tests/malloctest/malloctest.o'