#!/bin/bash

########################
# compile test program #
########################
pwd
cd tests/malloctest
rm -f *.o
make -j$(nproc)
cd ../../

########################
# build simulator Gem5 #
########################
source scons
scons build/X86/gem5.opt -j$(nproc)

test_dir="$(pwd)/tests/malloctest"

########################
#   start simulation   #
########################
# tests/malloctest/gen.o | \
build/X86/gem5.opt \
    configs/example/se.py \
    --caches --l1d_size=128B --l1i_size=128B \
    --mem-type=DDR3_1600_8x8 --mem-size=512MB --pool_ids='0,1;' \
    --sDMenable=true --fast_mode=0 --hash_lat=20 --enc_lat=20 --onchip_cache_size=4 --onchip_cache_lat=16 --dram_cache_size=2048 --lmem_lat=150 --rmem_lat=600 \
    --cpu-type=TimingSimpleCPU \
    --cmd="$test_dir/aes.o" 2> err.txt

# 默认cpu-clock=2GHz =>[1 Cycle = 0.5ns]
# lmem_lat同时控制了本地内存frontend时延以及dram cache时延
# rmem_lat控制了远端内存frontend时延

# --debug-flag=MemoryAccess --debug-file='mem.txt' \
# --caches --l1d_size=128B --l1i_size=128B \
# --l2cache --l2_size=1MB --l2_assoc=16 \