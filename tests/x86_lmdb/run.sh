cd libraries/liblmdb
make clean
if [ "$1" = "static" ]; then
    make -j$(nproc) && make install # link with libsdm
    cd ../../tests
    make clean
    make -j$(nproc) -f static-Makefile
else
    make -j$(nproc) -f origin.Makefile && make install -f origin.Makefile
    cd ../../tests
    make clean
    make -j$(nproc)
fi  