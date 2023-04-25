#!/bin/bash

pwd
cd tests/malloctest
rm -f malloctest.o
make
cd ../../

build/X86/gem5.opt configs/example/se.py  \
    --caches --l2cache  --l2_size=16kB \
    --num-l2caches=2 --mem-size=32MB --pool_ids='0;1' \
    --cpu-type=X86TimingSimpleCPU --num-cpu=2 \
    --cmd='/home/ys/Desktop/sDM/tests/malloctest/hello.o;/home/ys/Desktop/sDM/tests/malloctest/malloctest.o' \
     # -c tests/malloctest/malloctest.o \
