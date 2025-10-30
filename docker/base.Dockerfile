FROM ubuntu:22.04

RUN apt-get update && \
  apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev \
  python3-setuptools cargo libgtk-3-dev wget zip libtinfo5 libz-dev libzstd-dev libncurses5-dev libssl-dev && \
  apt-get install -y lld-15 llvm-15 llvm-15-dev clang-15 || apt-get install -y lld llvm llvm-dev clang && \
  apt-get install -y gcc-$(gcc --version | head -n1 | sed 's/.* //' | sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version | head -n1 | sed 's/.* //' | sed 's/\..*//')-dev && \
  apt-get install -y ninja-build meson # for some targets like harfbuzz

WORKDIR /opt

RUN git clone -b v3.23.5 https://github.com/Kitware/CMake.git cmake && \
  cd cmake && ./bootstrap && make -j$(nproc) && make install

RUN git clone -b poco-1.14.2-release https://github.com/pocoproject/poco.git && \
  cd poco && bash build_cmake.sh

RUN wget https://go.dev/dl/go1.25.3.linux-amd64.tar.gz && \
  rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.3.linux-amd64.tar.gz && \
  echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile && rm go1.25.3.linux-amd64.tar.gz

ENV PATH="${PATH}:/usr/local/go/bin:/root/go/bin"

RUN go install github.com/SRI-CSL/gllvm/cmd/...@latest

RUN git clone -b SVF-3.0 https://github.com/SVF-tools/SVF.git && cd SVF && bash ./build.sh

WORKDIR /root
RUN git clone https://github.com/grubwithu/hfc.git && cd hfc && mkdir build && cd build && cmake .. && make


