#!/bin/bash

env_file=""
# source scons # 在服务器中执行(非标准路径下的scon)
mkdir -p db
cd db && mkdir -p hello test
rm -rf hello/* test/*
cd ../
##########################
# compile m5 instruction #
##########################
cd util/m5
scons build/x86/out/m5 -j$(nproc)
cd ../../

#################################################
# compile test program libsdm && install libsdm # /util/m5/build/x86/out/libsdm.a
#################################################
# 用于静态库链接到lmdb以及test prog中
cd tests/malloctest
make -j$(nproc) && make install
cd ../

#####################################################
# compile test program liblmdb && install liblmdb.a # /tests/x86_lmdb/build
#####################################################
# 用于静态库链接到lmdb以及lmdb test prog中
cd x86_lmdb
if [ "$1" = "static" ]; then
    echo "[Static Mode]"
    ./run.sh static # use static lib 
else
    env_file="env.sh"
    ./run.sh
fi
cd ../../

#################################################
# compile malloc hook && install libmymalloc.so # /util/m5/build/x86/out/libmymalloc.so
#################################################
# 用于编译LD_PRELOAD动态重载的malloc,calloc等函数
cd hook
make -j$(nproc) && make install
cd ../

########################
# build simulator Gem5 #
########################
scons build/X86/gem5.opt -j$(nproc)
test_dir="$(pwd)/tests"
########## lmdb ##########
# mkdir -p $test_dir/db/$name
# ########## lmdb ##########

########################
#   start simulation   #
########################
build/X86/gem5.opt \
    configs/example/se.py \
    --caches --l1d_size=128B --l1i_size=128B \
    --l2cache --l2_size=1kB --l2_assoc=16 \
    --mem-type=DDR3_1600_8x8 --mem-size=512MB --pool_ids='0,1;' \
    --lmem_lat=150 --rmem_lat=600 \
    --sDMenable=true --fast_mode=1 \
    --hash_lat=20 --enc_lat=20 \
    --onchip_cache_size=4 --onchip_cache_lat=16 --dram_cache_size=256 \
    --addr_cache_size=32 --addr_cache_mode=0 --addr_cache_taglat=0 \
    --hot_page_cache_size=4 --hot_page_cache_ctr_filter_size=128 --hot_page_cache_backup_size=16 --hot_page_cache_threshold=2 \
    --cpu-type=TimingSimpleCPU \
    --cmd="$test_dir/malloctest/aes"
    # --env="$env_file" \
    # --cmd="$test_dir/x86_lmdb/tests/test.o"
# --cmd="$test_dir/malloctest/$pname"
# $test_dir/malloctest/aes.o
# $test_dir/x86_lmdb/tests/hello.o

# 默认cpu-clock=2GHz =>[1 Cycle = 0.5ns]
# lmem_lat同时控制了本地内存frontend时延以及dram cache时延
# rmem_lat控制了远端内存frontend时延

# --debug-flag=MemoryAccess --debug-file='mem.txt' \
# --caches --l1d_size=128B --l1i_size=128B \
# --l2cache --l2_size=1MB --l2_assoc=16 \
