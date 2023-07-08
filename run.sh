#!/bin/bash

test_dir="$(pwd)/tests/malloctest/"
pwd
cd tests/malloctest
rm -f *.o
make -j$(nproc)
cd ../../

scons build/X86/gem5.opt -j$(nproc)

# --debug-flag=MemoryAccess --debug-file='mem.txt' \
# --caches --l1d_size=128B --l1i_size=128B \
# --l2cache --l2_size=1MB --l2_assoc=16 \

# tests/malloctest/gen.o | \
build/X86/gem5.opt \
    configs/example/se.py \
    --caches --l1d_size=128B --l1i_size=128B \
    --mem-type=DDR3_1600_8x8 --mem-size=512MB --pool_ids='0,1;' \
    --sDMenable=true --fast_mode=0 --hash_lat=1 --enc_lat=1 --onchip_cache_size=2 --onchip_cache_lat=200 --dram_cache_size=16 \
    --cpu-type=O3CPU \
    --cmd="$test_dir/aes.o"