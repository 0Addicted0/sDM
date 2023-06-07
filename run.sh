#!/bin/bash

pwd
cd tests/malloctest
rm -f *.o
make
cd ../../

# scons build/X86/gem5.opt -j$(nproc)
#!/bin/bash
build/X86/gem5.opt \
    configs/example/se.py \
    --caches --l1d_size=32kB --l1i_size=32kB --l1i_assoc=2 --l1d_assoc=4\
    --l2cache --l2_size=1MB --l2_assoc=16\
    --num-l2caches=2 --mem-size=2GB --pool_ids='0,1;0,2' \
    --cpu-type=O3CPU --num-cpu=2 \
    --cmd='/home/ys/Desktop/sDM/tests/malloctest/src/sha512.o' \

#     configs/example/se.py --caches --l1d_size=1kB --l1i_size=1kB --l2cache --l2_size=16kB --num-l2caches=2 --mem-size=32MB --pool_ids='0,1;0,2' --cpu-type=X86TimingSimpleCPU --num-cpu=2 --cmd='/home/ys/Desktop/gem5/tests/malloctest/hello.o;/home/ys/Desktop/gem5/tests/malloctest/malloctest.o'