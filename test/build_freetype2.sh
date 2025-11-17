#!/bin/bash
set -e

cd freetype2
git checkout cd02d359

wget https://github.com/libarchive/libarchive/releases/download/v3.4.3/libarchive-3.4.3.tar.xz 
tar -xvf libarchive-3.4.3.tar.xz 
rm libarchive-3.4.3.tar.xz

pushd libarchive-3.4.3/
mkdir -p building
cd building
../configure --disable-shared --prefix=$(pwd)/install
make clean && make -j$(nproc) && make install
popd

bash autogen.sh # preinstall: libtool
mkdir -p build
pushd build
rm -rf *
export CXXFLAGS="-fsanitize=fuzzer-no-link -fuse-ld=gold -flto -g"
export CFLAGS="-fsanitize=fuzzer-no-link -fuse-ld=gold -flto -g"
../configure --disable-shared --prefix=$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no
make clean && FUZZ_INTROSPECTOR=1 make -j && make install
FUZZ_INTROSPECTOR=1 ${CC} -g -fsanitize=fuzzer -fuse-ld=gold -flto -std=c++11 \
  -I./install/include/ -I../include/ -I../libarchive-3.4.3/building/install/include/ \
  ../src/tools/ftfuzzer/ftfuzzer.cc  -o ftfuzzer \
  ./install/lib/libfreetype.a  ../libarchive-3.4.3/building/install/lib/libarchive.a
popd

mkdir -p build-runtime
pushd build-runtime
rm -rf *
export CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link -g"
export CFLAGS="-fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer-no-link -g"
../configure --disable-shared --prefix=$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no
make clean && make -j && make install
${CC} -fprofile-instr-generate -fcoverage-mapping -fsanitize=fuzzer -g -std=c++11 \
  -I./install/include/ -I../include/ -I../libarchive-3.4.3/building/install/include/ \
  ../src/tools/ftfuzzer/ftfuzzer.cc  -o ftfuzzer_cov \
  ./install/lib/libfreetype.a  ../libarchive-3.4.3/building/install/lib/libarchive.a
${CC} -fsanitize=fuzzer-no-link -g -std=c++11 -lstdc++ \
  -I./install/include/ -I../include/ -I../libarchive-3.4.3/building/install/include/ \
  ../src/tools/ftfuzzer/ftfuzzer.cc  -o ftfuzzer \
  ./install/lib/libfreetype.a  ../libarchive-3.4.3/building/install/lib/libarchive.a \
  ../../../pfuzzer/build/libfuzzer.a
popd
