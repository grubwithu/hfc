#!/bin/bash
# Run this script in the root directory of the project

export LLVM_CC_NAME=clang
export LLVM_CXX_NAME=clang++
export LLVM_LINK_NAME=llvm-link-14

export CC=gclang
export CXX=gclang++

pushd test
make clean && make
get-bc main.a
wpa -ander -dump-icfg main.a.bc
popd 

pushd build
cmake .. && make -j
popd

clang -g -fsanitize=fuzzer-no-link \
  -lstdc++ -lPocoFoundation -lPocoNet -lPocoUtil -lPocoXML -lPocoJSON \
  build/libhfc.a test/main.a -o build/test.out


