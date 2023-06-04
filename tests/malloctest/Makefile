TARGET_ISA=x86

GEM5_HOME=/home/ys/Desktop/sDM
$(info   GEM5_HOME is $(GEM5_HOME))

CXX=g++

CFLAGS=-I$(GEM5_HOME)/include 

LDFLAGS=-L$(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out -lm5 

OBJECTS= malloctest.o


all: malloctest

malloctest:
	$(CXX) -o $(OBJECTS) sort.cpp sdmmalloc.cpp $(CFLAGS) $(LDFLAGS) 
	$(CXX) -o hello.o hello.cpp

clean:
	rm -f $(LIBOBJECTS)