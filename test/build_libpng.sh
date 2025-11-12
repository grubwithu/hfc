#!/bin/bash

git submodule init
git submodule update

cd libpng
git checkout ba980b8 

mkdir -p build
cd build
rm -rf *

# Make sure CC and CXX is specified version
# Make sure ld is corresponding to the compiler

export CXXFLAGS="-fsanitize=fuzzer-no-link -fuse-ld=gold -flto -g"
export CFLAGS="-fsanitize=fuzzer-no-link -fuse-ld=gold -flto -g"

../configure --disable-shared && FUZZ_INTROSPECTOR=1 make -j 

FUZZ_INTROSPECTOR=1 ${CC} -g -fsanitize=fuzzer -fuse-ld=gold -flto \
  ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
  .libs/libpng16.a -lz -lm -lstdc++ \
  -o libpng_read_fuzzer

export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link -g"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link -g"

cd ..
mkdir -p build-runtime
cd build-runtime
rm -rf *

../configure --disable-shared && make -j 

${CC} -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer -g \
  ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
  .libs/libpng16.a -lz -lm -lstdc++ \
  -o libpng_read_fuzzer

