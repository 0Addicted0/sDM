TARGET_ISA=x86

GEM5_HOME = $(realpath $(CURDIR)/../../)
$(info   GEM5_HOME is $(GEM5_HOME))

CXX=g++
C=gcc
AR	= ar
OPT = -O3 -fpermissive -Wregister
W = 
CFLAGS = $(W) $(OPT) -I$(GEM5_HOME)/include 
LDFLAGS = -L$(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out -lm5 --static
prefix = $(GEM5_HOME)

ILIBS = libsdm.a
PROGS = aes malloctest gen graph bigint dhrystone primes qsort sha512 miniz 
libdir = $(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out

sdmmalloc.h = $(GEM5_HOME)/include/gem5/sdmmalloc.h

all: $(ILIBS) $(PROGS)

install: $(ILIBS)
# mkdir -p $(libdir)
	for f in $(ILIBS); do cp $$f $(libdir); done

libsdm.a: sdmmalloc.o
	$(AR) rs $@ sdmmalloc.o

aes: aes.o libsdm.a
malloctest: malloctest.o libsdm.a
gen: gen.o
graph: graph.o libsdm.a
bigint: bigint.o libsdm.a
dhrystone: dhrystone.o libsdm.a
primes: primes.o libsdm.a
qsort: qsort.o libsdm.a
sha512: sha512.o libsdm.a
norx: norx.o libsdm.a
miniz: miniz.o libsdm.a

sdmmalloc.o: sdmmalloc.cpp $(sdmmalloc.h)
	$(CXX) $(CFLAGS) $(LDFLAGS) -c sdmmalloc.cpp 

%: %.o
	$(CXX) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c $(sdmmalloc.h)
	$(CXX) $(CFLAGS) -c $< $(LDFLAGS)

%.o: %.cpp $(sdmmalloc.h)
	$(CXX) $(CFLAGS) -c $< $(LDFLAGS)

# aes.o:
# 	$(CXX) -o aes.o aes.c sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# malloctest.o: malloctest.cpp sdmmalloc.cpp $(sdmmalloc.h)
# 	$(CXX) -o malloctest.o malloctest.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# gen.o: gen.cpp sdmmalloc.cpp $(sdmmalloc.h)
# 	$(CXX) -o gen.o gen.cpp
# graph.o: graph.cpp sdmmalloc.cpp $(sdmmalloc.h)
# 	$(CXX) -o graph.o graph.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 

# $(CXX) -o demo.o demo.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o demo2.o demo2.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o demo3.o demo3.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o bigint.o bigint.cc sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o qsort.o qsort.c sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o sha512.o sha512.c sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
# $(CXX) -o primes.o primes.c sdmmalloc.cpp -lm $(CFLAGS) $(LDFLAGS) 
# $(C) -o miniz.o miniz.c
# $(C) -o norx.o norx.c
# $(C) -O -DREG=register dhrystone.c -o dhrystone.o

clean:
	rm -f $(PROGS) *.[ao]




