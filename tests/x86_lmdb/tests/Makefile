TARGET_ISA=x86

HOME = $(realpath $(CURDIR)/../)
$(info   LMDB_TEST_HOME is $(HOME))
GEM5_HOME = $(HOME)/../..

CXX=g++
C=gcc

CFLAGS = -I$(HOME)/build/include
LDFLAGS = -lpthread -L$(HOME)/build/lib -llmdb -L$(GEM5_HOME)/util/m5/build/$(TARGET_ISA)/out -lsdm -lm5

all:
	$(CXX) test.cpp $(CFLAGS) $(LDFLAGS) -o test.o
	$(C) hello.c $(CFLAGS) $(LDFLAGS) -o hello.o

clean:
	rm -f *.o
# g++ -I/home/yqy/x86_lmdb/build/include -L/home/yqy/x86_lmdb/build/lib test.cpp  -lpthread -llmdb -o test
# gcc -I/home/yqy/x86_lmdb/build/include -L/home/yqy/x86_lmdb/build/lib hello.c -lpthread -llmdb -o hello
