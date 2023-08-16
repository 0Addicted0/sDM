GEM5_HOME = $(realpath $(CURDIR)/../)# GEM5_HOME = gem5/

TARGET_ISA=x86
C=gcc
CXX=g++
libdir = $(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out
LDFLAGS	= -L$(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out -lm5
SOEXT	= .so
OPT = -O3
CFLAGS	= $(OPT) -I$(GEM5_HOME)/include
ILIBS = libmymalloc$(SOEXT)

all: $(ILIBS)
	$(CXX) main.cpp

install: $(ILIBS)
# mkdir -p $(libdir)
	for f in $(ILIBS); do cp $$f $(libdir); done

libmymalloc$(SOEXT):	mymalloc.lo
	$(C) -o $@ -shared -fPIC $^ $(CFLAGS) $(LDFLAGS)

mymalloc.lo:	mymalloc.c 
	$(C) -o $@ $(CFLAGS) -fPIC -c $^ $(CFLAGS) $(LDFLAGS)
clean:
	rm *.lo *.so *.o *.out
