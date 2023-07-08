TARGET_ISA=x86

GEM5_HOME = $(realpath $(CURDIR)/../../)
$(info   GEM5_HOME is $(GEM5_HOME))

CXX=g++
C=gcc

CFLAGS=-I$(GEM5_HOME)/include 

LDFLAGS=-L$(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out -lm5 

all:
	$(CXX) -o aes.o aes.c sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o demo3.o demo3.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
	$(CXX) -o malloctest.o malloctest.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o demo2.o demo2.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
	$(CXX) -o gen.o gen.cpp
	$(CXX) -o graph.o graph.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o demo.o demo.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o bigint.o bigint.cc sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o qsort.o qsort.c sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o sha512.o sha512.c sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o primes.o primes.c sdmmalloc.cpp -lm $(CFLAGS) $(LDFLAGS) 
# $(C) -o miniz.o miniz.c
# $(C) -o norx.o norx.c
# $(C) -O -DREG=register dhrystone.c -o dhrystone.o
clean:
	rm -f *.o




