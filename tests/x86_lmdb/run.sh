cd libraries/liblmdb
# make -j$(nproc) && make install # link with libsdm
make -j$(nproc) -f origin.Makefile && make install -f origin.Makefile
cd ../../tests
make -j$(nproc)
