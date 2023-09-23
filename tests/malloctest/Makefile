TARGET_ISA=x86

GEM5_HOME = $(realpath $(CURDIR)/../../)
$(info   GEM5_HOME is $(GEM5_HOME))

CXX=g++
C=gcc
AR	= ar
OPT = -O3 
W = 
CFLAGS = $(W) $(OPT) -DREG=register -I$(GEM5_HOME)/include
CXXFLAGS = $(W) $(OPT) -fpermissive -Wregister -I$(GEM5_HOME)/include
LDFLAGS = -L$(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out -lm5
LDLIBS = -L. -lsdm
FLAGS = --static
prefix = $(GEM5_HOME)

ILIBS = libsdm.a
PROGS = aes malloctest gen graph bigint dhrystone primes qsort sha512 miniz 
libdir = $(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out

sdmmalloc.h = $(GEM5_HOME)/include/gem5/sdmmalloc.h

all: $(ILIBS) $(PROGS)

install: $(ILIBS)
	mkdir -p $(libdir)
	for f in $(ILIBS); do cp $$f $(libdir); done

libsdm.a: sdmmalloc.o
	$(AR) rs $@ sdmmalloc.o

aes: aes.o
malloctest: malloctest.o 
gen: gen.o
graph: graph.o 
bigint: bigint.o 
dhrystone: dhrystone.o 
primes: primes.o 
qsort: qsort.o 
sha512: sha512.o 
norx: norx.o 
miniz: miniz.o 

sdmmalloc.o: sdmmalloc.c $(sdmmalloc.h)
	$(C) $(CFLAGS) $(LDFLAGS) $(FLAGS) -c sdmmalloc.c

%: %.o
	$(CXX) -o $@ $^ $(LDLIBS) $(LDFLAGS) $(FLAGS)

%.o: %.c $(sdmmalloc.h)
	$(C) $(CFLAGS) -c $< $(LDLIBS) $(LDFLAGS) $(FLAGS)

%.o: %.cpp $(sdmmalloc.h)
	$(CXX) $(CXXFLAGS) -c $< $(LDLIBS) $(LDFLAGS) $(FLAGS)

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




