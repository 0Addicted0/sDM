Gem5dir="$(pwd)/../../.."
export LD_LIBRARY_PATH="$Gem5dir/util/m5/build/x86/out:$Gem5dir/tests/x86_lmdb/build/lib:$LD_LIBRARY_PATH"
LD_PRELOAD="$Gem5dir/hook/libmymalloc.so" ./$1
unset LD_LIBRARY_PATH