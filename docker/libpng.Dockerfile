FROM hfc-base:latest

WORKDIR /root

RUN apt-get install -y file

RUN git clone https://github.com/pnggroup/libpng.git libpng && cd libpng && git checkout ba980b8 && \
  mkdir -p build-wllvm && cd build-wllvm && export LLVM_CC_NAME=clang-15 && export LLVM_LINK_NAME=llvm-link-15 && \
  CC=gclang CXX=gclang++ ../configure --disable-shared && make clean all -j$(nproc) && \
  gclang -g -fsanitize=fuzzer \
      ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
      -o libpng_read_fuzzer \
      .libs/libpng16.a \
      -lz -lm -lstdc++ && \
  get-bc libpng_read_fuzzer && \
  bash -c 'source /opt/SVF/setup.sh && wpa -ander -dump-icfg libpng_read_fuzzer.bc'

RUN mkdir -p libpng/build-hfc && cd libpng/build-hfc && \
  export LLVM_CC_NAME=clang-15 && export LLVM_LINK_NAME=llvm-link-15 && \
  CC=gclang CXX=gclang++ CFLAGS="-g -fsanitize=fuzzer-no-link" CSSFLAGS=$CFLAGS \
  ../configure --disable-shared && make clean all -j$(nproc) && \
  gclang -g -fsanitize=fuzzer-no-link \
      ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
      /root/hfc/build/libhfc.a .libs/libpng16.a -lz -lm -lstdc++ \
      -lPocoFoundation -lPocoNet -lPocoUtil -lPocoXML -lPocoJSON \
      -o libpng_read_fuzzer

