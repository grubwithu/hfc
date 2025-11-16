#!/bin/bash
set -e

cleanup() {
  kill $HFC_PID
  rm -rf tmp_xx223
}
trap cleanup EXIT INT TERM

# Make sure that the script is run from the root directory of the project
## 1. Compile HFC
make

## 2. Compile pfuzzer
pushd pfuzzer/
bash build.sh
popd

## 3. Compile libpng for demo
pushd test/
bash build_libpng.sh
### Prepare other fuzzers
pushd libpng/build-runtime/
docker cp pfuzzer:/libfuzzer/libpng_libpng_read_fuzzer/libpng.tar.gz . # TODO: remove this command
tar -zxvf libpng.tar.gz # TODO: remove this command
popd
popd

## 4. Run HFC
pushd test/libpng/
pushd build/
DATA_FILE=$(ls ./fuzzerLogFile*.data | head -n 1)
DATA_FILE_ABS=$(realpath $DATA_FILE)
YAML_FILE=$(ls ./fuzzerLogFile*.yaml | head -n 1)
YAML_FILE_ABS=$(realpath $YAML_FILE)
popd
pushd build-runtime/
PROG_FILE=$(realpath ./libpng_read_fuzzer_cov)
popd
popd
build/hfc -calltree=$DATA_FILE_ABS -profile=$YAML_FILE_ABS -program=$PROG_FILE & HFC_PID=$!
sleep 1

## 5. Run pfuzzer
mkdir -p tmp_xx223
AFL_SKIP_CPUFREQ=1 HFC_URL=http://localhost:8080 test/libpng/build-runtime/libpng_read_fuzzer tmp_xx223/ test/libpng_seeds/ -fork=2 -fuzzers=afl